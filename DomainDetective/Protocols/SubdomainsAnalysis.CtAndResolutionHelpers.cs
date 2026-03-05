using DnsClientX;
using AsyncIntervalGate = DnsClientX.Throttling.AsyncIntervalGate;
using DomainDetective.Helpers;
using DomainDetective.Network;
using DomainDetective.Providers.Dns;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class SubdomainsAnalysis : IHasAssessments
{
    private IReadOnlyList<string> ClassifyAiLabels(string fqdn, string baseDomain)
    {
        if (string.IsNullOrWhiteSpace(fqdn) || string.IsNullOrWhiteSpace(baseDomain))
        {
            return Array.Empty<string>();
        }

        var name = fqdn.Trim().TrimEnd('.');
        if (!name.EndsWith("." + baseDomain, StringComparison.OrdinalIgnoreCase))
        {
            return Array.Empty<string>();
        }

        var labels = name.Split('.');
        var baseLabels = baseDomain.Split('.');
        int take = labels.Length - baseLabels.Length;
        if (take <= 0)
        {
            return Array.Empty<string>();
        }

        var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < take; i++)
        {
            var label = labels[i];
            if (string.IsNullOrWhiteSpace(label))
            {
                continue;
            }

            if (SensitiveIgnoreLabels.Contains(label))
            {
                continue;
            }

            if (AiInfrastructureLabels.Contains(label))
            {
                matched.Add(label);
            }
        }

        return matched.Count > 0
            ? matched.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList()
            : Array.Empty<string>();
    }
    private void Reset()
    {
        Subject = null;
        QuerySucceeded = false;
        FailureReason = null;
        CertificateObservationCount = 0;
        ResultsCapped = false;
        FirstSeenUtc = null;
        LastSeenUtc = null;
        IssuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        Subdomains = Array.Empty<SubdomainDiscoveryEntry>();
        ResolutionReduced = false;
        Assessments.Clear();
        NativeCtLogDiagnostics = Array.Empty<string>();
        NativeCtLogDiagnosticEntries = Array.Empty<NativeCtLogDiagnosticEntry>();
    }

    private async Task<string> FetchJsonAsync(string url, CancellationToken cancellationToken)
    {
        if (QueryOverride != null)
        {
            return await QueryOverride(url, cancellationToken).ConfigureAwait(false);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        using var response = await SharedHttpClient.Instance.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    private string? BuildCrtShUrl(string domain)
    {
        if (string.IsNullOrWhiteSpace(CrtShUrlTemplate))
        {
            return null;
        }

        return string.Format(CrtShUrlTemplate, domain);
    }

    private string? BuildCertSpotterUrl(string domain)
    {
        if (string.IsNullOrWhiteSpace(CertSpotterUrlTemplate))
        {
            return null;
        }

        return string.Format(CertSpotterUrlTemplate, Uri.EscapeDataString(domain));
    }

    private async Task<NativeCtLogSubdomainDiscoveryResult> DiscoverNativeCtSubdomainsAsync(string domain, InternalLogger? logger, CancellationToken cancellationToken)
    {
        var source = new NativeCtLogSubdomainDiscovery
        {
            QueryOverride = QueryOverride
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions
        {
            BaseDomain = domain,
            MaxCtRowsToProcess = MaxCtRowsToProcess,
            MaxSubdomains = MaxSubdomains,
            LogListUrl = NativeCtLogListUrl,
            ExplicitLogUrls = NativeCtLogUrls.ToList(),
            MaxLogsToProcess = NativeCtMaxLogs,
            MaxEntriesPerLog = NativeCtMaxEntriesPerLog,
            EntryBatchSize = NativeCtEntryBatchSize,
            InitialBackfillEntriesPerLog = NativeCtInitialBackfillEntriesPerLog,
            CursorStatePath = NativeCtCursorStatePath,
            IncludePendingLogs = NativeCtIncludePendingLogs,
            RequestDelay = NativeCtRequestDelay,
            RetryCount = NativeCtRetryCount,
            RetryBaseDelay = NativeCtRetryBaseDelay,
            RetryMaxDelay = NativeCtRetryMaxDelay,
            CircuitBreakerFailureThreshold = NativeCtCircuitBreakerFailureThreshold,
            CircuitBreakerDuration = NativeCtCircuitBreakerDuration,
            EnableCatchUpMode = NativeCtEnableCatchUpMode,
            CatchUpLagThreshold = NativeCtCatchUpLagThreshold,
            CatchUpMaxEntriesPerLog = NativeCtCatchUpMaxEntriesPerLog,
            CatchUpBatchSize = NativeCtCatchUpBatchSize
        };

        return await source.DiscoverAsync(options, logger, cancellationToken).ConfigureAwait(false);
    }

    private void MergeNativeCtResult(
        NativeCtLogSubdomainDiscoveryResult nativeResult,
        Dictionary<string, int> issuerCounts,
        Dictionary<string, CtSubdomainAggregate> subdomainMap)
    {
        CertificateObservationCount += nativeResult.CertificateObservationCount;
        if (nativeResult.ResultsCapped)
        {
            ResultsCapped = true;
        }
        if (nativeResult.FirstSeenUtc.HasValue)
        {
            if (!FirstSeenUtc.HasValue || nativeResult.FirstSeenUtc.Value < FirstSeenUtc.Value)
            {
                FirstSeenUtc = nativeResult.FirstSeenUtc.Value;
            }
        }
        if (nativeResult.LastSeenUtc.HasValue)
        {
            if (!LastSeenUtc.HasValue || nativeResult.LastSeenUtc.Value > LastSeenUtc.Value)
            {
                LastSeenUtc = nativeResult.LastSeenUtc.Value;
            }
        }

        foreach (var kv in nativeResult.IssuerCounts)
        {
            issuerCounts[kv.Key] = issuerCounts.TryGetValue(kv.Key, out var existing) ? existing + kv.Value : kv.Value;
        }

        foreach (var kv in nativeResult.Subdomains)
        {
            if (!subdomainMap.TryGetValue(kv.Key, out CtSubdomainAggregate? existing))
            {
                subdomainMap[kv.Key] = new CtSubdomainAggregate
                {
                    FirstSeenUtc = kv.Value.First,
                    LastSeenUtc = kv.Value.Last
                };
                continue;
            }

            DateTimeOffset? first = existing.FirstSeenUtc;
            DateTimeOffset? last = existing.LastSeenUtc;
            if (kv.Value.First.HasValue && (!first.HasValue || kv.Value.First.Value < first.Value))
            {
                first = kv.Value.First.Value;
            }
            if (kv.Value.Last.HasValue && (!last.HasValue || kv.Value.Last.Value > last.Value))
            {
                last = kv.Value.Last.Value;
            }
            existing.FirstSeenUtc = first;
            existing.LastSeenUtc = last;
            existing.CtSources.Add("native-ct");
        }
    }

    private static IReadOnlyList<NativeCtLogDiagnosticEntry> BuildNativeCtLogDiagnosticEntries(
        IReadOnlyList<NativeCtLogIngestionStatus> statuses,
        string domain)
    {
        if (statuses == null || statuses.Count == 0)
        {
            return Array.Empty<NativeCtLogDiagnosticEntry>();
        }

        var output = new List<NativeCtLogDiagnosticEntry>(statuses.Count);
        foreach (var status in statuses)
        {
            if (status == null || string.IsNullOrWhiteSpace(status.LogUrl))
            {
                continue;
            }

            var scope = string.IsNullOrWhiteSpace(status.DomainScope) ? domain : status.DomainScope!;
            output.Add(new NativeCtLogDiagnosticEntry {
                Scope = scope,
                SharedIngestion = status.SharedIngestion,
                State = status.SkippedByCircuitBreaker ? "CircuitOpen" : (status.Succeeded ? "Succeeded" : "Failed"),
                LogUrl = status.LogUrl,
                TreeSize = status.TreeSize,
                LastProcessedIndex = status.LastProcessedIndex,
                LagBefore = status.EstimatedLagBefore,
                LagAfter = status.EstimatedLagAfter,
                CircuitOpenUntilUtc = status.CircuitOpenUntilUtc,
                Failure = string.IsNullOrWhiteSpace(status.Failure)
                    ? null
                    : status.Failure!.Replace('\r', ' ').Replace('\n', ' ').Trim()
            });
        }

        return output;
    }

    private static string FormatNativeCtLogDiagnostic(NativeCtLogDiagnosticEntry entry)
    {
        var scope = string.IsNullOrWhiteSpace(entry.Scope) ? "unknown" : entry.Scope;
        var state = string.IsNullOrWhiteSpace(entry.State) ? "Unknown" : entry.State;
        var lagBefore = entry.LagBefore.HasValue ? entry.LagBefore.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var lagAfter = entry.LagAfter.HasValue ? entry.LagAfter.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var treeSize = entry.TreeSize.HasValue ? entry.TreeSize.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var lastProcessed = entry.LastProcessedIndex.HasValue ? entry.LastProcessedIndex.Value.ToString(CultureInfo.InvariantCulture) : "-";
        var circuitUntil = entry.CircuitOpenUntilUtc.HasValue ? entry.CircuitOpenUntilUtc.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture) : "-";
        var failure = string.IsNullOrWhiteSpace(entry.Failure) ? "-" : entry.Failure!;
        return $"scope={scope}; shared={entry.SharedIngestion}; state={state}; log={entry.LogUrl}; tree={treeSize}; last={lastProcessed}; lagBefore={lagBefore}; lagAfter={lagAfter}; circuitUntil={circuitUntil}; failure={failure}";
    }

    private void ParseCtJson(
        string json,
        string baseDomain,
        Dictionary<string, int> issuerCounts,
        Dictionary<string, CtSubdomainAggregate> subdomainMap,
        InternalLogger? logger,
        string sourceName)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return;
        }

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (MaxCtRowsToProcess > 0 && CertificateObservationCount >= MaxCtRowsToProcess)
            {
                ResultsCapped = true;
                break;
            }

            CertificateObservationCount++;

            var issuer = GetIssuerName(item);
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                issuerCounts[issuer!] = issuerCounts.TryGetValue(issuer!, out var c) ? c + 1 : 1;
            }

            string? serialNumber = GetString(item, "serial_number");
            string? commonName = GetCommonName(item);
            DateTimeOffset? notBeforeUtc = ParseTimestamp(GetString(item, "not_before"));
            DateTimeOffset? notAfterUtc = ParseTimestamp(GetString(item, "not_after"));
            var ts = GetString(item, "entry_timestamp") ?? GetString(item, "not_before");
            DateTimeOffset? entryTimestampUtc = ParseTimestamp(ts);
            if (entryTimestampUtc.HasValue)
            {
                DateTimeOffset entryTs = entryTimestampUtc.Value;
                FirstSeenUtc = !FirstSeenUtc.HasValue ? entryTs : (entryTs < FirstSeenUtc.Value ? entryTs : FirstSeenUtc.Value);
                LastSeenUtc = !LastSeenUtc.HasValue ? entryTs : (entryTs > LastSeenUtc.Value ? entryTs : LastSeenUtc.Value);
            }

            var candidateNames = GetCandidateNames(item);
            if (candidateNames.Count == 0)
            {
                continue;
            }

            foreach (var name in candidateNames)
            {
                var normalized = NormalizeCandidate(name);
                if (normalized == null)
                {
                    continue;
                }

                // Ensure it is a strict subdomain of baseDomain (exclude the base itself)
                if (!normalized.EndsWith("." + baseDomain, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (string.Equals(normalized, baseDomain, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // IDN normalization (throws on invalid)
                try
                {
                    normalized = DomainHelper.ValidateIdn(normalized);
                }
                catch
                {
                    continue;
                }

                if (!subdomainMap.TryGetValue(normalized, out CtSubdomainAggregate? agg))
                {
                    if (MaxSubdomains > 0 && subdomainMap.Count >= MaxSubdomains)
                    {
                        ResultsCapped = true;
                        break;
                    }
                    agg = new CtSubdomainAggregate();
                    subdomainMap[normalized] = agg;
                }

                agg.CertificateObservationCount++;
                if (!string.IsNullOrWhiteSpace(sourceName))
                {
                    agg.CtSources.Add(sourceName);
                }

                if (entryTimestampUtc.HasValue)
                {
                    DateTimeOffset seen = entryTimestampUtc.Value;
                    if (!agg.FirstSeenUtc.HasValue || seen < agg.FirstSeenUtc.Value)
                    {
                        agg.FirstSeenUtc = seen;
                    }

                    if (!agg.LastSeenUtc.HasValue || seen > agg.LastSeenUtc.Value)
                    {
                        agg.LastSeenUtc = seen;
                    }
                }

                bool shouldUpdateLatest = !agg.LatestCertificateCtEntryTimestampUtc.HasValue;
                if (entryTimestampUtc.HasValue &&
                    (!agg.LatestCertificateCtEntryTimestampUtc.HasValue ||
                     entryTimestampUtc.Value >= agg.LatestCertificateCtEntryTimestampUtc.Value))
                {
                    shouldUpdateLatest = true;
                }

                if (shouldUpdateLatest)
                {
                    agg.LatestCertificateCtEntryTimestampUtc = entryTimestampUtc;
                    agg.LatestCertificateSubject = string.IsNullOrWhiteSpace(commonName)
                        ? normalized
                        : commonName;
                    agg.LatestCertificateIssuer = issuer;
                    agg.LatestCertificateSerialNumber = serialNumber;
                    agg.LatestCertificateNotBeforeUtc = notBeforeUtc;
                    agg.LatestCertificateNotAfterUtc = notAfterUtc;
                }
            }

            if (ResultsCapped)
            {
                break;
            }
        }

        if (subdomainMap.Count > 0)
        {
            logger?.WriteVerbose("CT discovered {0} subdomain(s) for {1}", subdomainMap.Count, baseDomain);
        }
    }

    private async Task VerifyResolutionAsync(List<SubdomainDiscoveryEntry> entries, CancellationToken cancellationToken)
    {
        if (entries.Count == 0)
        {
            return;
        }

        var cap = MaxResolutionChecks <= 0 ? 0 : MaxResolutionChecks;
        if (cap == 0)
        {
            ResolutionReduced = true;
            return;
        }

        if (entries.Count > cap)
        {
            ResolutionReduced = true;
        }

        var toCheck = entries.Take(cap).ToList();
        var concurrency = ResolutionConcurrency <= 0 ? 1 : ResolutionConcurrency;
        var minInterval = ResolutionMinInterval;
        if (minInterval < TimeSpan.Zero)
        {
            minInterval = TimeSpan.Zero;
        }

        AsyncIntervalGate? rateGate = null;
        if (minInterval > TimeSpan.Zero)
        {
            rateGate = new AsyncIntervalGate(minInterval);
        }

        using var sem = new SemaphoreSlim(concurrency, concurrency);
        var tasks = toCheck.Select(async e =>
        {
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var a = await QueryDnsWithRateLimitAsync(e.Name, DnsRecordType.A, rateGate, cancellationToken).ConfigureAwait(false);
                var aaaa = await QueryDnsWithRateLimitAsync(e.Name, DnsRecordType.AAAA, rateGate, cancellationToken).ConfigureAwait(false);

                var aVals = (a ?? Array.Empty<DnsAnswer>())
                    .Select(x => x.Data ?? x.DataRaw ?? string.Empty)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(10)
                    .ToList();
                var aaaaVals = (aaaa ?? Array.Empty<DnsAnswer>())
                    .Select(x => x.Data ?? x.DataRaw ?? string.Empty)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(10)
                    .ToList();

                e.ARecords = aVals;
                e.AaaaRecords = aaaaVals;
                e.ResolutionStatus = (aVals.Count > 0 || aaaaVals.Count > 0) ? SubdomainResolutionStatus.Resolves : SubdomainResolutionStatus.DoesNotResolve;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                e.ResolutionStatus = SubdomainResolutionStatus.QueryFailed;
            }
            finally
            {
                sem.Release();
            }
        }).ToList();

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            rateGate?.Dispose();
        }
    }

	    private async Task<DnsAnswer[]?> QueryDnsWithRateLimitAsync(string name, DnsRecordType type, AsyncIntervalGate? rateGate, CancellationToken cancellationToken)
	    {
	        cancellationToken.ThrowIfCancellationRequested();
	        if (rateGate != null)
	        {
	            await rateGate.WaitAsync(cancellationToken).ConfigureAwait(false);
	        }
	        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken).ConfigureAwait(false);
	    }

	    private static string? NormalizeCandidate(string value)
	    {
	        if (string.IsNullOrWhiteSpace(value))
	        {
            return null;
        }

        var s = value.Trim().TrimEnd('.');
        if (s.StartsWith("*.", StringComparison.Ordinal))
        {
            s = s.Substring(2);
        }

        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    private static string? GetString(JsonElement obj, string prop)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(prop, out var p))
        {
            return null;
        }

        return p.ValueKind == JsonValueKind.String ? p.GetString() : p.ToString();
    }

    private static string? GetIssuerName(JsonElement obj)
    {
        var direct = GetString(obj, "issuer_name");
        if (!string.IsNullOrWhiteSpace(direct))
        {
            return direct;
        }

        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty("issuer", out var issuer))
        {
            return null;
        }

        if (issuer.ValueKind == JsonValueKind.String)
        {
            return issuer.GetString();
        }

        if (issuer.ValueKind == JsonValueKind.Object)
        {
            return GetString(issuer, "name") ?? GetString(issuer, "common_name") ?? GetString(issuer, "organization");
        }

        return null;
    }

    private static List<string> GetCandidateNames(JsonElement obj)
    {
        var names = new List<string>();

        var nameValue = GetString(obj, "name_value");
        if (!string.IsNullOrWhiteSpace(nameValue))
        {
            names.AddRange(nameValue!.Split('\n'));
        }

        if (obj.ValueKind == JsonValueKind.Object &&
            obj.TryGetProperty("dns_names", out var dnsNames) &&
            dnsNames.ValueKind == JsonValueKind.Array)
        {
            foreach (var dnsName in dnsNames.EnumerateArray())
            {
                if (dnsName.ValueKind == JsonValueKind.String)
                {
                    var value = dnsName.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        names.Add(value!);
                    }
                }
            }
        }

        return names;
    }

    private static bool TryParseTimestamp(string? value, out DateTimeOffset result)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            result = default;
            return false;
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out result))
        {
            return true;
        }

        return DateTimeOffset.TryParse(value, out result);
    }

    private static DateTimeOffset? ParseTimestamp(string? value)
    {
        return TryParseTimestamp(value, out DateTimeOffset result)
            ? result
            : null;
    }

    private static string? GetCommonName(JsonElement item)
    {
        string? commonName = GetString(item, "common_name");
        if (!string.IsNullOrWhiteSpace(commonName))
        {
            return commonName;
        }

        if (item.ValueKind == JsonValueKind.Object &&
            item.TryGetProperty("dns_names", out JsonElement dnsNames) &&
            dnsNames.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement dnsName in dnsNames.EnumerateArray())
            {
                if (dnsName.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                string? value = dnsName.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return null;
    }

}
