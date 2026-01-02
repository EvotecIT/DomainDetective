using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Discovers subdomains using certificate transparency (CT) data and (optionally) verifies
/// whether each discovered name still resolves in DNS.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class SubdomainsAnalysis : IHasAssessments
{
    /// <summary>The domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS configuration used for optional resolution verification.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>CT query template used for fetching candidate subdomains.</summary>
    public string CrtShUrlTemplate { get; set; } = "https://crt.sh/?q=%25.{0}&output=json";

    /// <summary>
    /// Optional override returning the JSON payload for a given CT URL.
    /// Used by tests and offline callers.
    /// </summary>
    public Func<string, CancellationToken, Task<string>>? QueryOverride { get; set; }

    /// <summary>True when CT query succeeded and parsing produced results.</summary>
    public bool QuerySucceeded { get; private set; }

    /// <summary>If <see cref="QuerySucceeded"/> is false, this may contain a short reason.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Total number of CT rows observed (may include duplicates).</summary>
    public int CertificateObservationCount { get; private set; }

    /// <summary>Earliest CT entry timestamp observed.</summary>
    public DateTimeOffset? FirstSeenUtc { get; private set; }

    /// <summary>Latest CT entry timestamp observed.</summary>
    public DateTimeOffset? LastSeenUtc { get; private set; }

    /// <summary>Distinct issuer count observed in CT data.</summary>
    public int DistinctIssuerCount => IssuerCounts.Count;

    /// <summary>Issuer name → count (best-effort).</summary>
    public IReadOnlyDictionary<string, int> IssuerCounts { get; private set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Discovered subdomains ordered by last-seen descending.</summary>
    public IReadOnlyList<SubdomainDiscoveryEntry> Subdomains { get; private set; } = Array.Empty<SubdomainDiscoveryEntry>();

    /// <summary>When true, DNS resolution checks were capped and not all subdomains were verified.</summary>
    public bool ResolutionReduced { get; private set; }

    /// <summary>
    /// When true (default), attempts to verify whether discovered subdomains still resolve.
    /// </summary>
    public bool VerifyStillResolves { get; set; } = true;

    /// <summary>
    /// Maximum number of subdomains to verify for DNS resolution.
    /// Remaining entries will have <see cref="SubdomainResolutionStatus.Unknown"/>.
    /// </summary>
    public int MaxResolutionChecks { get; set; } = 500;

    /// <summary>Maximum number of concurrent DNS checks for subdomain resolution.</summary>
    public int ResolutionConcurrency { get; set; } = 20;

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Performs CT-backed subdomain discovery for the specified <paramref name="domain"/>.
    /// </summary>
    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);

        string json;
        try
        {
            var url = string.Format(CrtShUrlTemplate, Subject);
            json = await FetchJsonAsync(url, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "Subdomains",
                Code = SubdomainCodes.CtQueryFailed,
                Target = Subject,
                Message = $"CT query failed: {ex.Message}"
            });
            return;
        }

        var issuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var subdomainMap = new Dictionary<string, (DateTimeOffset? First, DateTimeOffset? Last)>(StringComparer.OrdinalIgnoreCase);

        try
        {
            ParseCtJson(json, Subject, issuerCounts, subdomainMap, logger);
            QuerySucceeded = true;
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "Subdomains",
                Code = SubdomainCodes.CtParseFailed,
                Target = Subject,
                Message = $"CT response parsing failed: {ex.Message}"
            });
            return;
        }

        IssuerCounts = issuerCounts;

        var entries = new List<SubdomainDiscoveryEntry>(subdomainMap.Count);
        foreach (var kv in subdomainMap)
        {
            entries.Add(new SubdomainDiscoveryEntry
            {
                Name = kv.Key,
                FirstSeenUtc = kv.Value.First,
                LastSeenUtc = kv.Value.Last,
                ResolutionStatus = SubdomainResolutionStatus.Unknown
            });
        }

        entries = entries
            .OrderByDescending(e => e.LastSeenUtc ?? DateTimeOffset.MinValue)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (VerifyStillResolves && entries.Count > 0)
        {
            await VerifyResolutionAsync(entries, cancellationToken).ConfigureAwait(false);
        }

        Subdomains = entries;

        if (CertificateObservationCount == 0 || entries.Count == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "Subdomains",
                Code = SubdomainCodes.CtNoResults,
                Target = Subject,
                Message = "No CT-backed subdomains found."
            });
        }
        else
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "Subdomains",
                Code = SubdomainCodes.CtResultsPresent,
                Target = Subject,
                Message = $"Discovered {entries.Count} subdomain(s) from CT data."
            });
        }

        if (ResolutionReduced)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "Subdomains",
                Code = SubdomainCodes.ResolutionReduced,
                Target = Subject,
                Message = $"DNS verification capped at {MaxResolutionChecks} subdomain(s)."
            });
        }
    }

    private void Reset()
    {
        Subject = null;
        QuerySucceeded = false;
        FailureReason = null;
        CertificateObservationCount = 0;
        FirstSeenUtc = null;
        LastSeenUtc = null;
        IssuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        Subdomains = Array.Empty<SubdomainDiscoveryEntry>();
        ResolutionReduced = false;
        Assessments.Clear();
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

    private void ParseCtJson(
        string json,
        string baseDomain,
        Dictionary<string, int> issuerCounts,
        Dictionary<string, (DateTimeOffset? First, DateTimeOffset? Last)> subdomainMap,
        InternalLogger? logger)
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
            CertificateObservationCount++;

            var issuer = GetString(item, "issuer_name");
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                issuerCounts[issuer!] = issuerCounts.TryGetValue(issuer!, out var c) ? c + 1 : 1;
            }

            var ts = GetString(item, "entry_timestamp");
            if (TryParseTimestamp(ts, out var entryTs))
            {
                FirstSeenUtc = !FirstSeenUtc.HasValue ? entryTs : (entryTs < FirstSeenUtc.Value ? entryTs : FirstSeenUtc.Value);
                LastSeenUtc = !LastSeenUtc.HasValue ? entryTs : (entryTs > LastSeenUtc.Value ? entryTs : LastSeenUtc.Value);
            }

            var namesRaw = GetString(item, "name_value");
            if (string.IsNullOrWhiteSpace(namesRaw))
            {
                continue;
            }

            foreach (var name in namesRaw!.Split('\n'))
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

                DateTimeOffset? seen = null;
                if (TryParseTimestamp(ts, out var parsed))
                {
                    seen = parsed;
                }

                if (!subdomainMap.TryGetValue(normalized, out var agg))
                {
                    subdomainMap[normalized] = (seen, seen);
                }
                else
                {
                    var first = agg.First;
                    var last = agg.Last;
                    if (seen.HasValue)
                    {
                        if (!first.HasValue || seen.Value < first.Value) first = seen.Value;
                        if (!last.HasValue || seen.Value > last.Value) last = seen.Value;
                    }
                    subdomainMap[normalized] = (first, last);
                }
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

        using var sem = new SemaphoreSlim(concurrency, concurrency);
        var tasks = toCheck.Select(async e =>
        {
            await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var a = await DnsConfiguration.QueryDNS(e.Name, DnsRecordType.A, cancellationToken: cancellationToken).ConfigureAwait(false);
                var aaaa = await DnsConfiguration.QueryDNS(e.Name, DnsRecordType.AAAA, cancellationToken: cancellationToken).ConfigureAwait(false);
                e.ResolutionStatus = (a.Length > 0 || aaaa.Length > 0) ? SubdomainResolutionStatus.Resolves : SubdomainResolutionStatus.DoesNotResolve;
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

        await Task.WhenAll(tasks).ConfigureAwait(false);
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
}

/// <summary>Resolution status for a discovered subdomain.</summary>
public enum SubdomainResolutionStatus
{
    Unknown = 0,
    Resolves = 1,
    DoesNotResolve = 2,
    QueryFailed = 3
}

/// <summary>Represents a subdomain discovered from CT data.</summary>
public sealed class SubdomainDiscoveryEntry
{
    public string Name { get; init; } = string.Empty;
    public DateTimeOffset? FirstSeenUtc { get; init; }
    public DateTimeOffset? LastSeenUtc { get; init; }
    public SubdomainResolutionStatus ResolutionStatus { get; internal set; }
}
