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
public sealed partial class SubdomainsAnalysis : IHasAssessments
{
    /// <summary>The domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS configuration used for optional resolution verification.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>CT query template used for fetching candidate subdomains.</summary>
    public string CrtShUrlTemplate { get; set; } = "https://crt.sh/?q=%25.{0}&output=json";

    /// <summary>Fallback CT query template used when crt.sh is unavailable.</summary>
    public string CertSpotterUrlTemplate { get; set; } = "https://api.certspotter.com/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names";

    /// <summary>When true (default), queries Cert Spotter when crt.sh cannot be reached.</summary>
    public bool UseCertSpotterFallback { get; set; } = true;

    /// <summary>Per-request timeout for passive/public CT HTTP calls.</summary>
    public TimeSpan PassiveCtRequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum retry count for transient passive/public CT HTTP failures.</summary>
    public int PassiveCtRetryCount { get; set; } = 2;

    /// <summary>Base delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(750);

    /// <summary>Maximum delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryMaxDelay { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Cooldown applied to passive/public CT sources after transient failures or rate limits.</summary>
    public TimeSpan PassiveCtSourceCooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>When true, uses direct RFC6962 CT log polling as primary subdomain discovery source.</summary>
    public bool EnableNativeCtLogSource { get; set; }

    /// <summary>When true, only native CT log polling is used (disables crt.sh/Cert Spotter fallback).</summary>
    public bool NativeCtLogOnly { get; set; }

    /// <summary>CT log list URL used by native CT discovery.</summary>
    public string NativeCtLogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    /// <summary>Optional explicit CT log URLs for native discovery (skips log-list download when provided).</summary>
    public List<string> NativeCtLogUrls { get; } = new();

    /// <summary>Maximum CT logs processed per native run (0 means all).</summary>
    public int NativeCtMaxLogs { get; set; } = 12;

    /// <summary>Maximum CT entries processed per log in a native run (0 means uncapped).</summary>
    public int NativeCtMaxEntriesPerLog { get; set; } = 2_000;

    /// <summary>Maximum get-entries batch size per native CT request.</summary>
    public int NativeCtEntryBatchSize { get; set; } = 256;

    /// <summary>Initial per-log backfill window when no native CT cursor exists (0 starts at current tree head).</summary>
    public int NativeCtInitialBackfillEntriesPerLog { get; set; } = 2_000;

    /// <summary>Optional native CT cursor state path used to persist per-domain/per-log progress.</summary>
    public string? NativeCtCursorStatePath { get; set; }

    /// <summary>When true, includes pending CT logs from the log list during native discovery.</summary>
    public bool NativeCtIncludePendingLogs { get; set; }

    /// <summary>When true, includes retired CT logs during native discovery to recover older historical certificates.</summary>
    public bool NativeCtIncludeRetiredLogs { get; set; } = true;

    /// <summary>
    /// When true, native CT discovery only matches the exact requested host instead of only child subdomains.
    /// Useful for direct host or subdomain lookups where the caller wants CT data for that exact name.
    /// </summary>
    public bool NativeCtExactMatchOnly { get; set; }

    /// <summary>
    /// When true, exact-host native CT discovery prefers newer CT logs first so the latest certificate
    /// metadata can be returned faster for direct host lookups.
    /// </summary>
    public bool NativeCtPrioritizeLatestExactMatch { get; set; }

    /// <summary>
    /// Optional matched-observation stop target for exact-host native CT discovery.
    /// Set to values greater than zero to stop after enough exact-host evidence has been observed.
    /// </summary>
    public int NativeCtStopAfterMatchedObservations { get; set; }

    /// <summary>Optional delay between native CT HTTP requests.</summary>
    public TimeSpan NativeCtRequestDelay { get; set; } = TimeSpan.Zero;

    /// <summary>Per-request timeout for native CT HTTP calls.</summary>
    public TimeSpan NativeCtRequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum retry count for transient native CT HTTP failures.</summary>
    public int NativeCtRetryCount { get; set; } = 3;

    /// <summary>Base delay between native CT retry attempts.</summary>
    public TimeSpan NativeCtRetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Maximum delay between native CT retry attempts.</summary>
    public TimeSpan NativeCtRetryMaxDelay { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Consecutive native CT failures required before opening circuit breaker for a log.</summary>
    public int NativeCtCircuitBreakerFailureThreshold { get; set; } = 3;

    /// <summary>Base native CT circuit-breaker duration per log after repeated failures.</summary>
    public TimeSpan NativeCtCircuitBreakerDuration { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>When true, native CT polling automatically expands caps when cursor lag is large.</summary>
    public bool NativeCtEnableCatchUpMode { get; set; } = true;

    /// <summary>Cursor lag threshold at/above which native CT catch-up mode is activated.</summary>
    public int NativeCtCatchUpLagThreshold { get; set; } = 50_000;

    /// <summary>Maximum CT entries processed per log while native CT catch-up mode is active.</summary>
    public int NativeCtCatchUpMaxEntriesPerLog { get; set; } = 20_000;

    /// <summary>Maximum get-entries batch size used while native CT catch-up mode is active.</summary>
    public int NativeCtCatchUpBatchSize { get; set; } = 1_024;

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

    /// <summary>Native CT per-log diagnostics captured during this analysis run.</summary>
    public IReadOnlyList<string> NativeCtLogDiagnostics { get; private set; } = Array.Empty<string>();

    /// <summary>Structured native CT per-log diagnostics captured during this analysis run.</summary>
    public IReadOnlyList<NativeCtLogDiagnosticEntry> NativeCtLogDiagnosticEntries { get; private set; } = Array.Empty<NativeCtLogDiagnosticEntry>();

    /// <summary>Passive/public CT source warnings captured during this analysis run.</summary>
    public IReadOnlyList<string> PassiveCtWarnings { get; private set; } = Array.Empty<string>();

    /// <summary>Structured passive/public CT source diagnostics captured during this analysis run.</summary>
    public IReadOnlyList<PassiveCtDiagnosticEntry> PassiveCtDiagnosticEntries { get; private set; } = Array.Empty<PassiveCtDiagnosticEntry>();

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

        var issuerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var subdomainMap = new Dictionary<string, CtSubdomainAggregate>(StringComparer.OrdinalIgnoreCase);
        string? failure = null;
        var sourceSucceeded = false;

        if (EnableNativeCtLogSource)
        {
            try
            {
                var nativeResult = await DiscoverNativeCtSubdomainsAsync(Subject, logger, cancellationToken).ConfigureAwait(false);
                foreach (var warning in nativeResult.Warnings)
                {
                    logger?.WriteVerbose("{0}", warning);
                }
                NativeCtLogDiagnosticEntries = BuildNativeCtLogDiagnosticEntries(nativeResult.LogStatuses, Subject);
                NativeCtLogDiagnostics = NativeCtLogDiagnosticEntries
                    .Select(FormatNativeCtLogDiagnostic)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .ToList()!;
                if (nativeResult.SourceSucceeded)
                {
                    sourceSucceeded = true;
                    MergeNativeCtResult(nativeResult, issuerCounts, subdomainMap);
                }
                else if (nativeResult.Warnings.Count > 0)
                {
                    failure = string.Join("; ", nativeResult.Warnings.Take(3));
                }
            }
            catch (Exception ex)
            {
                failure = ex.Message;
                logger?.WriteVerbose("Native CT source failed for {0}: {1}", Subject, ex.Message);
            }
        }

        var payloads = new List<(string SourceName, string Payload)>(2);
        var shouldTryPassiveCt = !NativeCtLogOnly && (!sourceSucceeded || (EnableNativeCtLogSource && subdomainMap.Count == 0));
        if (shouldTryPassiveCt)
        {
            PassiveCtSourceClient.QueryResult passiveResult = await QueryPassiveCtSourcesAsync(Subject, logger, cancellationToken).ConfigureAwait(false);
            PassiveCtWarnings = passiveResult.Warnings
                .Where(static warning => !string.IsNullOrWhiteSpace(warning))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            PassiveCtDiagnosticEntries = BuildPassiveCtDiagnosticEntries(passiveResult.Diagnostics, Subject, "SubdomainDiscovery");
            foreach (PassiveCtSourceClient.SourcePayload payload in passiveResult.Payloads)
            {
                payloads.Add((payload.SourceName, payload.Payload));
            }

            if (payloads.Count == 0 && PassiveCtWarnings.Count > 0)
            {
                failure = string.Join("; ", PassiveCtWarnings.Take(3));
            }
        }

        if (!sourceSucceeded && payloads.Count == 0)
        {
            QuerySucceeded = false;
            FailureReason = failure ?? "No CT source succeeded.";
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "Subdomains",
                Code = SubdomainCodes.CtQueryFailed,
                Target = Subject,
                Message = $"CT query failed: {FailureReason}"
            });
            return;
        }

        try
        {
            bool anyPayloadParsed = sourceSucceeded;
            foreach (var payload in payloads)
            {
                try
                {
                    anyPayloadParsed |= ParseCtJson(payload.Payload, Subject, issuerCounts, subdomainMap, logger, payload.SourceName);
                }
                catch (JsonException ex)
                {
                    failure = string.IsNullOrWhiteSpace(failure)
                        ? ex.Message
                        : failure + "; " + ex.Message;
                    logger?.WriteVerbose(
                        "Passive CT source payload failed for {0} via {1}: {2}",
                        Subject,
                        payload.SourceName,
                        ex.Message);
                }

                if (ResultsCapped)
                {
                    break;
                }
            }

            if (!anyPayloadParsed)
            {
                throw new InvalidOperationException(failure ?? "No CT source returned a parseable array payload.");
            }

            QuerySucceeded = true;
        }
        catch (JsonException ex)
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
        catch (InvalidOperationException ex)
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
                FirstSeenUtc = kv.Value.FirstSeenUtc,
                LastSeenUtc = kv.Value.LastSeenUtc,
                LatestCertificateCtEntryTimestampUtc = kv.Value.LatestCertificateCtEntryTimestampUtc,
                LatestCertificateSubject = kv.Value.LatestCertificateSubject,
                LatestCertificateIssuer = kv.Value.LatestCertificateIssuer,
                LatestCertificateSerialNumber = kv.Value.LatestCertificateSerialNumber,
                LatestCertificateNotBeforeUtc = kv.Value.LatestCertificateNotBeforeUtc,
                LatestCertificateNotAfterUtc = kv.Value.LatestCertificateNotAfterUtc,
                CtSources = kv.Value.CtSources
                    .OrderBy(source => source, StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                CertificateObservationCount = kv.Value.CertificateObservationCount,
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
    public DateTimeOffset? LatestCertificateCtEntryTimestampUtc { get; init; }
    public string? LatestCertificateSubject { get; init; }
    public string? LatestCertificateIssuer { get; init; }
    public string? LatestCertificateSerialNumber { get; init; }
    public DateTimeOffset? LatestCertificateNotBeforeUtc { get; init; }
    public DateTimeOffset? LatestCertificateNotAfterUtc { get; init; }
    public IReadOnlyList<string> CtSources { get; init; } = Array.Empty<string>();
    public int CertificateObservationCount { get; init; }
    public SubdomainResolutionStatus ResolutionStatus { get; internal set; }
    public IReadOnlyList<string> ARecords { get; internal set; } = Array.Empty<string>();
    public IReadOnlyList<string> AaaaRecords { get; internal set; } = Array.Empty<string>();
    public SensitiveSubdomainRisk SensitiveRisk { get; internal set; } = SensitiveSubdomainRisk.None;
    public IReadOnlyList<string> SensitiveSignals { get; internal set; } = Array.Empty<string>();
    public IReadOnlyList<string> AiSignals { get; internal set; } = Array.Empty<string>();
}

internal sealed class CtSubdomainAggregate
{
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public DateTimeOffset? LatestCertificateCtEntryTimestampUtc { get; set; }
    public string? LatestCertificateSubject { get; set; }
    public string? LatestCertificateIssuer { get; set; }
    public string? LatestCertificateSerialNumber { get; set; }
    public DateTimeOffset? LatestCertificateNotBeforeUtc { get; set; }
    public DateTimeOffset? LatestCertificateNotAfterUtc { get; set; }
    public int CertificateObservationCount { get; set; }
    public HashSet<string> CtSources { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Risk rating for sensitive subdomain naming patterns.</summary>
public enum SensitiveSubdomainRisk
{
    None = 0,
    Moderate = 1,
    High = 2
}

