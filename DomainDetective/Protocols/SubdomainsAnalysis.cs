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

    /// <summary>True when processing was capped to protect performance.</summary>
    public bool ResultsCapped { get; private set; }

    /// <summary>Maximum number of CT rows to process.</summary>
    public int MaxCtRowsToProcess { get; set; } = 10_000;

    /// <summary>Maximum number of distinct subdomains to retain.</summary>
    public int MaxSubdomains { get; set; } = 10_000;

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

    /// <summary>
    /// Minimum interval between DNS queries performed during subdomain resolution verification.
    /// Set to <see cref="TimeSpan.Zero"/> (default) to disable rate limiting.
    /// </summary>
    public TimeSpan ResolutionMinInterval { get; set; } = TimeSpan.Zero;

    /// <summary>When true (default), flags discovered subdomains with sensitive/admin-sounding labels.</summary>
    public bool DetectSensitiveSubdomains { get; set; } = true;

    /// <summary>When true, flags discovered subdomains with AI/ML tooling labels (best-effort).</summary>
    public bool DetectAiInfrastructureExposure { get; set; }

    /// <summary>When true (default), scans TXT records on sensitive subdomains for suspicious content.</summary>
    public bool ScanSensitiveSubdomainTxt { get; set; } = true;

    /// <summary>Maximum number of sensitive subdomains to scan for TXT content.</summary>
    public int MaxSensitiveSubdomainTxtScans { get; set; } = 25;

    /// <summary>High-risk labels (exact label match) used for sensitive subdomain detection.</summary>
    public HashSet<string> SensitiveHighLabels { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "admin",
        "administrator",
        "auth",
        "login",
        "sso",
        "vpn",
        "remote",
        "rdp",
        "ssh",
        "smtp",
        "imap",
        "pop",
        "pop3",
        "webmail",
        "owa",
        "intranet"
    };

    /// <summary>Moderate-risk labels (exact label match) used for sensitive subdomain detection.</summary>
    public HashSet<string> SensitiveModerateLabels { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "dev",
        "test",
        "qa",
        "uat",
        "stage",
        "staging",
        "preprod",
        "sandbox",
        "payments",
        "payment",
        "billing",
        "finance"
    };

    /// <summary>AI/ML tooling labels (exact label match) used for exposure detection.</summary>
    public HashSet<string> AiInfrastructureLabels { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "jupyter",
        "notebook",
        "mlflow",
        "tensorboard",
        "kubeflow",
        "sagemaker",
        "vertex",
        "databricks",
        "airflow",
        "prefect",
        "dagster",
        "ray",
        "wandb"
    };

    /// <summary>Labels excluded from sensitive detection (exact label match).</summary>
    public HashSet<string> SensitiveIgnoreLabels { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "www",
        "mail",
        "mta-sts",
        "autodiscover"
    };

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

        if (DetectSensitiveSubdomains && entries.Count > 0)
        {
            await DetectSensitiveAsync(entries, cancellationToken).ConfigureAwait(false);
        }

        if (DetectAiInfrastructureExposure && entries.Count > 0)
        {
            await DetectAiInfrastructureAsync(entries, cancellationToken).ConfigureAwait(false);
        }

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

        if (ResultsCapped)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "Subdomains",
                Code = SubdomainCodes.CtResultsCapped,
                Target = Subject,
                Message = $"CT processing capped at {Math.Max(0, MaxCtRowsToProcess)} row(s) / {Math.Max(0, MaxSubdomains)} subdomain(s)."
            });
        }
    }

    private async Task DetectSensitiveAsync(List<SubdomainDiscoveryEntry> entries, CancellationToken cancellationToken)
    {
        if (!DetectSensitiveSubdomains || string.IsNullOrWhiteSpace(Subject))
        {
            return;
        }

        var high = new List<string>();
        var moderate = new List<string>();
        var nonPublic = new List<string>();
        foreach (var e in entries)
        {
            if (e == null || e.ResolutionStatus != SubdomainResolutionStatus.Resolves)
            {
                continue;
            }

            var (risk, matched) = ClassifySensitiveLabels(e.Name, Subject!);
            e.SensitiveRisk = risk;
            e.SensitiveSignals = matched;

            if (e.ARecords != null)
            {
                foreach (var ip in e.ARecords)
                {
                    if (IpAddressClassifier.TryClassify(ip, out var vis) && IpAddressClassifier.IsNonPublic(vis))
                    {
                        if (nonPublic.Count < 10)
                        {
                            nonPublic.Add($"{e.Name} -> {ip} ({vis})");
                        }
                    }
                }
            }
            if (e.AaaaRecords != null)
            {
                foreach (var ip in e.AaaaRecords)
                {
                    if (IpAddressClassifier.TryClassify(ip, out var vis) && IpAddressClassifier.IsNonPublic(vis))
                    {
                        if (nonPublic.Count < 10)
                        {
                            nonPublic.Add($"{e.Name} -> {ip} ({vis})");
                        }
                    }
                }
            }

            if (risk == SensitiveSubdomainRisk.High)
            {
                if (high.Count < 20)
                {
                    high.Add(e.Name);
                }
            }
            else if (risk == SensitiveSubdomainRisk.Moderate)
            {
                if (moderate.Count < 20)
                {
                    moderate.Add(e.Name);
                }
            }
        }

        if (high.Count == 0 && moderate.Count == 0)
        {
            return;
        }

        if (high.Count > 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "Subdomains",
                Code = SubdomainCodes.SensitiveSubdomainsHigh,
                Target = Subject,
                Message = $"Sensitive subdomains detected (high risk): {string.Join(", ", high.Take(10))}{(high.Count > 10 ? " (+more)" : string.Empty)}"
            });
        }
        if (moderate.Count > 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "Subdomains",
                Code = SubdomainCodes.SensitiveSubdomainsModerate,
                Target = Subject,
                Message = $"Sensitive subdomains detected (moderate risk): {string.Join(", ", moderate.Take(10))}{(moderate.Count > 10 ? " (+more)" : string.Empty)}"
            });
        }

        if (ScanSensitiveSubdomainTxt)
        {
            await ScanSensitiveTxtAsync(entries, cancellationToken).ConfigureAwait(false);
        }

        if (nonPublic.Count > 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "Subdomains",
                Code = SubdomainCodes.NonPublicIpAddress,
                Target = Subject,
                Message = $"Non-public IP address(es) returned for subdomain(s): {string.Join(", ", nonPublic)}"
            });
        }
    }

    private async Task DetectAiInfrastructureAsync(List<SubdomainDiscoveryEntry> entries, CancellationToken cancellationToken)
    {
        await Task.Yield();

        if (!DetectAiInfrastructureExposure || string.IsNullOrWhiteSpace(Subject))
        {
            return;
        }

        var matches = new List<string>();
        foreach (var e in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (e == null || e.ResolutionStatus != SubdomainResolutionStatus.Resolves)
            {
                continue;
            }

            var matched = ClassifyAiLabels(e.Name, Subject!);
            e.AiSignals = matched;

            if (matched.Count > 0 && matches.Count < 20)
            {
                matches.Add(e.Name);
            }
        }

        if (matches.Count == 0)
        {
            return;
        }

        Assessments.Add(new Assessment
        {
            Severity = AssessmentSeverity.Info,
            Category = "Subdomains",
            Code = SubdomainCodes.AiInfrastructureExposed,
            Target = Subject,
            Message = $"AI/ML tooling-like subdomains detected: {string.Join(", ", matches.Take(10))}{(matches.Count > 10 ? " (+more)" : string.Empty)}"
        });
    }

    private async Task ScanSensitiveTxtAsync(List<SubdomainDiscoveryEntry> entries, CancellationToken cancellationToken)
    {
        try
        {
            int cap = MaxSensitiveSubdomainTxtScans <= 0 ? 0 : MaxSensitiveSubdomainTxtScans;
            if (cap == 0)
            {
                return;
            }

            var names = entries
                .Where(e => e != null && e.ResolutionStatus == SubdomainResolutionStatus.Resolves && e.SensitiveRisk != SensitiveSubdomainRisk.None)
                .OrderByDescending(e => e.SensitiveRisk == SensitiveSubdomainRisk.High)
                .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .Take(cap)
                .Select(e => e.Name)
                .ToList();

            if (names.Count == 0)
            {
                return;
            }

            var tuples = new List<(string Name, string Value)>();
            foreach (var name in names)
            {
                var answers = await DnsConfiguration.QueryDNS(name, DnsRecordType.TXT, cancellationToken: cancellationToken).ConfigureAwait(false);
                foreach (var a in answers ?? Array.Empty<DnsAnswer>())
                {
                    var data = a.DataRaw ?? a.Data ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(data))
                    {
                        tuples.Add((name, data));
                    }
                }

                var nullAnswers = await DnsConfiguration.QueryDNS(name, DnsRecordType.NULL, cancellationToken: cancellationToken).ConfigureAwait(false);
                foreach (var a in nullAnswers ?? Array.Empty<DnsAnswer>())
                {
                    var data = a.DataRaw ?? a.Data ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(data))
                    {
                        tuples.Add((name, data));
                    }
                }
            }

            var match = DnsTxtMalwareDetector.Detect(tuples, maxFindings: 5, maxEvidence: 6);
            if (match.Findings.Count == 0)
            {
                return;
            }

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "Subdomains",
                Code = SubdomainCodes.SensitiveTxtSuspicious,
                Target = Subject,
                Message = match.Evidence.Count > 0 ? $"Suspicious TXT content on sensitive subdomain(s): {match.Evidence[0]}" : "Suspicious TXT content detected on sensitive subdomain(s)."
            });
        }
        catch
        {
        }
    }

    private (SensitiveSubdomainRisk Risk, IReadOnlyList<string> Matched) ClassifySensitiveLabels(string fqdn, string baseDomain)
    {
        if (string.IsNullOrWhiteSpace(fqdn) || string.IsNullOrWhiteSpace(baseDomain))
        {
            return (SensitiveSubdomainRisk.None, Array.Empty<string>());
        }

        var name = fqdn.Trim().TrimEnd('.');
        if (!name.EndsWith("." + baseDomain, StringComparison.OrdinalIgnoreCase))
        {
            return (SensitiveSubdomainRisk.None, Array.Empty<string>());
        }

        var labels = name.Split('.');
        var baseLabels = baseDomain.Split('.');
        int take = labels.Length - baseLabels.Length;
        if (take <= 0)
        {
            return (SensitiveSubdomainRisk.None, Array.Empty<string>());
        }

        var matchedHigh = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var matchedModerate = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

            if (SensitiveHighLabels.Contains(label))
            {
                matchedHigh.Add(label);
            }
            else if (SensitiveModerateLabels.Contains(label))
            {
                matchedModerate.Add(label);
            }
        }

        if (matchedHigh.Count > 0)
        {
            return (SensitiveSubdomainRisk.High, matchedHigh.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
        }
        if (matchedModerate.Count > 0)
        {
            return (SensitiveSubdomainRisk.Moderate, matchedModerate.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
        }

        return (SensitiveSubdomainRisk.None, Array.Empty<string>());
    }

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
            if (MaxCtRowsToProcess > 0 && CertificateObservationCount >= MaxCtRowsToProcess)
            {
                ResultsCapped = true;
                break;
            }

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
                    if (MaxSubdomains > 0 && subdomainMap.Count >= MaxSubdomains)
                    {
                        ResultsCapped = true;
                        break;
                    }
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
    public IReadOnlyList<string> ARecords { get; internal set; } = Array.Empty<string>();
    public IReadOnlyList<string> AaaaRecords { get; internal set; } = Array.Empty<string>();
    public SensitiveSubdomainRisk SensitiveRisk { get; internal set; } = SensitiveSubdomainRisk.None;
    public IReadOnlyList<string> SensitiveSignals { get; internal set; } = Array.Empty<string>();
    public IReadOnlyList<string> AiSignals { get; internal set; } = Array.Empty<string>();
}

/// <summary>Risk rating for sensitive subdomain naming patterns.</summary>
public enum SensitiveSubdomainRisk
{
    None = 0,
    Moderate = 1,
    High = 2
}
