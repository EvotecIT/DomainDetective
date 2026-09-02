using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;
using DomainDetective.Network;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Performs a lightweight DNS inventory for a domain by querying common record types and capturing
/// answers (and optionally authority/additional sections) with TTLs for reporting.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed partial class DnsInventoryAnalysis : IHasAssessments
{
    /// <summary>The domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>DNS configuration used for queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>
    /// Optional override returning a full DNS response for a given (name,type) query.
    /// Used by tests and offline callers.
    /// </summary>
    public Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? QueryOverride { get; set; }

    /// <summary>True when the inventory completed (even if some record types returned no data).</summary>
    public bool QuerySucceeded { get; private set; }

    /// <summary>If <see cref="QuerySucceeded"/> is false, this may contain a short reason.</summary>
    public string? FailureReason { get; private set; }

    /// <summary>Total number of record types attempted.</summary>
    public int RecordTypesQueried { get; private set; }

    /// <summary>Number of record type queries that failed.</summary>
    public int RecordTypesFailed { get; private set; }

    /// <summary>Total number of captured records across all queries.</summary>
    public int TotalRecords { get; private set; }

    /// <summary>Best-effort inferred DNS provider based on NS/SOA patterns.</summary>
    public DnsProvider Provider { get; private set; } = DnsProvider.Unknown;

    /// <summary>Score used for provider inference (higher = more matches).</summary>
    public int ProviderScore { get; private set; }

    /// <summary>Short evidence strings explaining provider inference.</summary>
    public IReadOnlyList<string> ProviderEvidence { get; private set; } = Array.Empty<string>();

    /// <summary>Best-effort inferred mail provider based on MX patterns.</summary>
    public MailProviderKind MailProvider { get; private set; } = MailProviderKind.Unknown;

    /// <summary>Score used for mail provider inference (higher = more matches).</summary>
    public int MailProviderScore { get; private set; }

    /// <summary>Short evidence strings explaining mail provider inference.</summary>
    public IReadOnlyList<string> MailProviderEvidence { get; private set; } = Array.Empty<string>();

    /// <summary>Best-effort inferred provider for apex CNAME target.</summary>
    public DnsCnameTargetProvider CnameTargetProvider { get; private set; } = DnsCnameTargetProvider.Unknown;

    /// <summary>Best-effort inferred managed service for the apex CNAME target.</summary>
    public DnsCnameTargetService CnameTargetService { get; private set; } = DnsCnameTargetService.Unknown;

    /// <summary>Flags describing the apex CNAME target (best-effort).</summary>
    public DnsCnameTargetFlags CnameTargetFlags { get; private set; } = DnsCnameTargetFlags.None;

    /// <summary>Short evidence strings explaining CNAME target inference.</summary>
    public IReadOnlyList<string> CnameTargetEvidence { get; private set; } = Array.Empty<string>();

    /// <summary>Signals inferred from TXT records (apex).</summary>
    public DnsTxtSignals TxtSignals { get; private set; } = DnsTxtSignals.None;

    /// <summary>Short evidence strings explaining TXT signal inference.</summary>
    public IReadOnlyList<string> TxtSignalsEvidence { get; private set; } = Array.Empty<string>();

    /// <summary>Typed applications and services inferred from DNS provider, mail provider, and TXT evidence.</summary>
    public IReadOnlyList<DetectedDnsApplication> DetectedDnsApplications { get; private set; } = Array.Empty<DetectedDnsApplication>();

    /// <summary>Issuers inferred from CAA records (apex).</summary>
    public DnsCaaIssuers CaaIssuers { get; private set; } = DnsCaaIssuers.None;

    /// <summary>Short evidence strings explaining CAA issuer inference.</summary>
    public IReadOnlyList<string> CaaIssuersEvidence { get; private set; } = Array.Empty<string>();

    /// <summary>When true (default), includes authority section records where present.</summary>
    public bool IncludeAuthorities { get; set; } = true;

    /// <summary>When true, includes additional section records where present.</summary>
    public bool IncludeAdditional { get; set; }

    /// <summary>Maximum number of records captured per DNS section (answers/authority/additional).</summary>
    public int MaxRecordsPerSection { get; set; } = 200;

    /// <summary>Maximum number of concurrent DNS queries for the inventory.</summary>
    public int QueryConcurrency { get; set; } = 4;

    /// <summary>Inventory profile controlling which record types are queried.</summary>
    public DnsInventoryProfile Profile { get; set; } = DnsInventoryProfile.Standard;

    /// <summary>When true, performs a lightweight IPv6 readiness roll-up (apex + MX/NS host AAAA).</summary>
    public bool EvaluateIpv6Readiness { get; set; } = true;

    /// <summary>Maximum number of MX/NS hostnames queried for AAAA during IPv6 readiness roll-up.</summary>
    public int MaxIpv6ReadinessHostChecks { get; set; } = 20;

    /// <summary>Queries captured for each record type.</summary>
    public IReadOnlyList<DnsInventoryQuery> Queries { get; private set; } = Array.Empty<DnsInventoryQuery>();

    /// <summary>Assessment collection for report-friendly output.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Performs a DNS inventory for the specified <paramref name="domain"/>.
    /// </summary>
    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        Reset();
        Subject = DomainHelper.ValidateIdn(domain);

        var recordTypes = Profile == DnsInventoryProfile.Extended ? ExtendedRecordTypes : DefaultRecordTypes;
        RecordTypesQueried = recordTypes.Length;

        var results = new DnsInventoryQuery[recordTypes.Length];
        var concurrency = QueryConcurrency <= 0 ? 1 : QueryConcurrency;
        using var sem = new SemaphoreSlim(concurrency, concurrency);

        var tasks = new List<Task>(recordTypes.Length);
        for (int i = 0; i < recordTypes.Length; i++)
        {
            int idx = i;
            var type = recordTypes[i];
            tasks.Add(Task.Run(async () =>
            {
                await sem.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    results[idx] = await QueryTypeAsync(Subject!, type, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    sem.Release();
                }
            }, cancellationToken));
        }

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
            QuerySucceeded = true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            QuerySucceeded = false;
            FailureReason = ex.Message;
        }

        var list = results.Where(r => r != null).ToList();
        Queries = list;

        RecordTypesFailed = list.Count(q => q.Status == DnsInventoryQueryStatus.Failed);
        TotalRecords = list.Sum(q => q.Records.Count);

        TryDetectProvider(list);
        TryDetectMailProvider(list);
        TryDetectCnameTarget(list);
        TryDetectTxtSignals(list);
        DetectedDnsApplications = DetectedDnsApplicationCatalog.DetectFromInventory(this);
        TryDetectTxtSignalsExposure();
        TryDetectCaaIssuers(list);
        TryDetectApexAaaaMissing(list);
        TryDetectPrivateIpAnswers(list);
        TryDetectTxtMalware(list);
        TryDetectServiceDiscoveryExposure(list);
        await TryDetectIpv6ReadinessAsync(list, cancellationToken).ConfigureAwait(false);

        if (!QuerySucceeded)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Error,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.InventoryFailed,
                Target = Subject,
                Message = $"DNS inventory failed: {FailureReason}"
            });
            return;
        }

        foreach (var q in list.Where(q => q.Status == DnsInventoryQueryStatus.Failed))
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.QueryFailed,
                Target = Subject,
                Message = $"{q.RecordType}: query failed{(string.IsNullOrWhiteSpace(q.FailureReason) ? "." : $": {q.FailureReason}")}"
            });
        }

        if (TotalRecords == 0)
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.NoRecords,
                Target = Subject,
                Message = "No DNS records were captured for the queried record types."
            });
        }
        else
        {
            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.ResultsPresent,
                Target = Subject,
                Message = $"Captured {TotalRecords} DNS record(s) across {RecordTypesQueried} record type(s)."
            });
        }

        logger?.WriteVerbose("DNS inventory captured {0} record(s) across {1} type(s) for {2}.", TotalRecords, RecordTypesQueried, Subject);
    }

    private void TryDetectApexAaaaMissing(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0 || string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var a = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.A);
            var aaaa = queries.FirstOrDefault(q => q.RecordType == DnsRecordType.AAAA);
            if (a == null || aaaa == null)
            {
                return;
            }

            bool hasA = a.Records.Any(r => r.Section == DnsInventorySection.Answer && r.Type == DnsRecordType.A);
            bool hasAaaa = aaaa.Records.Any(r => r.Section == DnsInventorySection.Answer && r.Type == DnsRecordType.AAAA);
            if (hasA && !hasAaaa)
            {
                Assessments.Add(new Assessment
                {
                    Severity = AssessmentSeverity.Info,
                    Category = "DNS Inventory",
                    Code = DnsInventoryCodes.ApexAaaaMissing,
                    Target = Subject,
                    Message = "Apex AAAA record missing (A is present)."
                });
            }
        }
        catch
        {
        }
    }

    private void TryDetectPrivateIpAnswers(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0 || string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var nonPublic = new List<string>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.A && q.RecordType != DnsRecordType.AAAA)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer)
                    {
                        continue;
                    }

                    if (!IpAddressClassifier.TryClassify(r.Data, out var vis))
                    {
                        continue;
                    }

                    if (IpAddressClassifier.IsNonPublic(vis))
                    {
                        if (nonPublic.Count < 10)
                        {
                            nonPublic.Add($"{r.Data} ({vis})");
                        }
                    }
                }
            }

            if (nonPublic.Count == 0)
            {
                return;
            }

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.NonPublicIpAddress,
                Target = Subject,
                Message = $"Non-public IP address(es) returned in A/AAAA: {string.Join(", ", nonPublic)}"
            });
        }
        catch
        {
        }
    }

    private void TryDetectTxtMalware(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (queries == null || queries.Count == 0 || string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var records = new List<(string Name, string Value)>();
            foreach (var q in queries)
            {
                if (q.RecordType != DnsRecordType.TXT && q.RecordType != DnsRecordType.NULL)
                {
                    continue;
                }

                foreach (var r in q.Records)
                {
                    if (r.Section != DnsInventorySection.Answer || (r.Type != DnsRecordType.TXT && r.Type != DnsRecordType.NULL))
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(r.Data))
                    {
                        records.Add((r.Name, r.Data));
                    }
                }
            }

            var match = DnsTxtMalwareDetector.Detect(records, maxFindings: 5, maxEvidence: 6);
            if (match.Findings.Count == 0)
            {
                return;
            }

            var msg = match.Evidence.Count > 0
                ? $"Suspicious TXT/NULL content detected: {match.Evidence[0]}"
                : "Suspicious content detected in DNS TXT/NULL records.";

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.TxtSuspiciousContent,
                Target = Subject,
                Message = msg
            });
        }
        catch
        {
        }
    }

    private void TryDetectServiceDiscoveryExposure(List<DnsInventoryQuery> queries)
    {
        try
        {
            if (Profile != DnsInventoryProfile.Extended)
            {
                return;
            }

            if (queries == null || queries.Count == 0 || string.IsNullOrWhiteSpace(Subject))
            {
                return;
            }

            var exposedTypes = new HashSet<DnsRecordType>();
            foreach (var q in queries)
            {
                if (!ServiceDiscoveryTypes.Contains(q.RecordType))
                {
                    continue;
                }

                if (q.Records.Any(r => r.Section == DnsInventorySection.Answer))
                {
                    exposedTypes.Add(q.RecordType);
                }
            }

            if (exposedTypes.Count == 0)
            {
                return;
            }

            Assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Category = "DNS Inventory",
                Code = DnsInventoryCodes.ServiceDiscoveryExposed,
                Target = Subject,
                Message = $"Service discovery record(s) present: {string.Join(", ", exposedTypes.OrderBy(t => t.ToString()))}"
            });
        }
        catch
        {
        }
    }

    private async Task<DnsInventoryQuery> QueryTypeAsync(string name, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        try
        {
            var response = await QueryResponseAsync(name, recordType, cancellationToken).ConfigureAwait(false);
            if (response == null)
            {
                return new DnsInventoryQuery
                {
                    RecordType = recordType,
                    Status = DnsInventoryQueryStatus.Failed,
                    FailureReason = "No response."
                };
            }

            var q = new DnsInventoryQuery
            {
                RecordType = recordType,
                ResponseStatus = response.Status,
                Status = DnsInventoryQueryStatus.Success
            };

            var max = MaxRecordsPerSection <= 0 ? 0 : MaxRecordsPerSection;

            AddRecords(q, DnsInventorySection.Answer, response.Answers, max);
            if (IncludeAuthorities)
            {
                AddRecords(q, DnsInventorySection.Authority, response.Authorities, max);
            }
            if (IncludeAdditional)
            {
                AddRecords(q, DnsInventorySection.Additional, response.Additional, max);
            }

            if (q.Records.Count == 0)
            {
                q.Status = DnsInventoryQueryStatus.NoData;
            }

            return q;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new DnsInventoryQuery
            {
                RecordType = recordType,
                Status = DnsInventoryQueryStatus.Failed,
                FailureReason = ex.Message
            };
        }
    }

    private async Task<DnsResponse?> QueryResponseAsync(string name, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        if (QueryOverride != null)
        {
            return await QueryOverride(name, recordType, cancellationToken).ConfigureAwait(false);
        }

        var list = await DnsConfiguration.QueryFullDNS(new[] { name }, recordType, cancellationToken: cancellationToken).ConfigureAwait(false);
        return list.FirstOrDefault();
    }

    private static void AddRecords(DnsInventoryQuery q, DnsInventorySection section, DnsAnswer[]? answers, int max)
    {
        if (q == null)
        {
            return;
        }

        if (answers == null || answers.Length == 0)
        {
            return;
        }

        int take = max <= 0 ? 0 : Math.Min(max, answers.Length);
        for (int i = 0; i < take; i++)
        {
            var a = answers[i];
            q.Records.Add(new DnsInventoryRecord
            {
                Section = section,
                Name = a.Name ?? string.Empty,
                Type = a.Type,
                Ttl = a.TTL,
                Data = a.DataRaw ?? a.Data ?? string.Empty
            });
        }
    }

    private void Reset()
    {
        Subject = null;
        QuerySucceeded = false;
        FailureReason = null;
        RecordTypesQueried = 0;
        RecordTypesFailed = 0;
        TotalRecords = 0;
        Provider = DnsProvider.Unknown;
        ProviderScore = 0;
        ProviderEvidence = Array.Empty<string>();
        MailProvider = MailProviderKind.Unknown;
        MailProviderScore = 0;
        MailProviderEvidence = Array.Empty<string>();
        CnameTargetProvider = DnsCnameTargetProvider.Unknown;
        CnameTargetService = DnsCnameTargetService.Unknown;
        CnameTargetFlags = DnsCnameTargetFlags.None;
        CnameTargetEvidence = Array.Empty<string>();
        TxtSignals = DnsTxtSignals.None;
        TxtSignalsEvidence = Array.Empty<string>();
        DetectedDnsApplications = Array.Empty<DetectedDnsApplication>();
        CaaIssuers = DnsCaaIssuers.None;
        CaaIssuersEvidence = Array.Empty<string>();
        Queries = Array.Empty<DnsInventoryQuery>();
        Assessments.Clear();
    }

    private static DnsRecordType[] DefaultRecordTypes => new[]
    {
        DnsRecordType.A,
        DnsRecordType.AAAA,
        DnsRecordType.CNAME,
        DnsRecordType.MX,
        DnsRecordType.NS,
        DnsRecordType.SOA,
        DnsRecordType.TXT,
        DnsRecordType.CAA
    };

    private static DnsRecordType[] ExtendedRecordTypes => new[]
    {
        // Baseline
        DnsRecordType.A,
        DnsRecordType.AAAA,
        DnsRecordType.CNAME,
        DnsRecordType.MX,
        DnsRecordType.NS,
        DnsRecordType.SOA,
        DnsRecordType.TXT,
        DnsRecordType.CAA,

        // Service discovery / metadata
        DnsRecordType.SRV,
        DnsRecordType.NAPTR,
        DnsRecordType.URI,
        DnsRecordType.HINFO,
        DnsRecordType.LOC,
        DnsRecordType.RP,
        DnsRecordType.KX,
        DnsRecordType.CERT,
        DnsRecordType.SPF,
        DnsRecordType.NULL,

        // Crypto / security
        DnsRecordType.DS,
        DnsRecordType.DNSKEY,
        DnsRecordType.RRSIG,
        DnsRecordType.NSEC,
        DnsRecordType.NSEC3,
        DnsRecordType.NSEC3PARAM,
        DnsRecordType.SSHFP,
        DnsRecordType.IPSECKEY,
        DnsRecordType.TLSA,
        DnsRecordType.SMIMEA,
        DnsRecordType.OPENPGPKEY,

        // Modern HTTP aliasing / service binding
        DnsRecordType.SVCB,
        DnsRecordType.HTTPS
    };

    private static readonly HashSet<DnsRecordType> ServiceDiscoveryTypes = new()
    {
        DnsRecordType.SRV,
        DnsRecordType.NAPTR,
        DnsRecordType.URI,
        DnsRecordType.HINFO,
        DnsRecordType.LOC,
        DnsRecordType.RP
    };
}

/// <summary>Status of an inventory query for a specific record type.</summary>
public enum DnsInventoryQueryStatus
{
    /// <summary>Defines values for dns inventory section.</summary>
    Success = 0,
    /// <summary>Defines values for dns inventory section.</summary>
    NoData = 1,
    /// <summary>Defines values for dns inventory section.</summary>
    Failed = 2
}

/// <summary>DNS response section where a record was captured from.</summary>
public enum DnsInventorySection
{
    /// <summary>Represents captured data.</summary>
    Answer = 0,
    /// <summary>Represents captured data.</summary>
    Authority = 1,
    /// <summary>Represents captured data.</summary>
    Additional = 2
}

/// <summary>A single DNS record captured for inventory/reporting.</summary>
public sealed class DnsInventoryRecord
{
    /// <summary>Gets or sets the section value.</summary>
    public DnsInventorySection Section { get; init; }
    /// <summary>Gets or sets the name value.</summary>
    public string Name { get; init; } = string.Empty;
    /// <summary>Gets or sets the type value.</summary>
    public DnsRecordType Type { get; init; }
    /// <summary>Gets or sets the ttl value.</summary>
    public int Ttl { get; init; }
    /// <summary>Gets or sets the data value.</summary>
    public string Data { get; init; } = string.Empty;
}

/// <summary>Inventory result for a specific record type.</summary>
public sealed class DnsInventoryQuery
{
    /// <summary>Gets or sets the record type value.</summary>
    public DnsRecordType RecordType { get; init; }
    /// <summary>Gets or sets the status value.</summary>
    public DnsInventoryQueryStatus Status { get; internal set; }
    /// <summary>Gets or sets the response status value.</summary>
    public DnsResponseCode ResponseStatus { get; internal set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; internal set; }
    /// <summary>Gets the records value.</summary>
    public List<DnsInventoryRecord> Records { get; } = new();
}

/// <summary>DNS inventory profile controlling the record types queried.</summary>
public enum DnsInventoryProfile
{
    /// <summary>Represents the standard value.</summary>
    Standard = 0,
    /// <summary>Represents the extended value.</summary>
    Extended = 1
}

