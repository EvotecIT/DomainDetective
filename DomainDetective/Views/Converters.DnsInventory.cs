using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static DnsInventoryInfo Convert(DnsInventoryAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        var refs = new[]
        {
            new StandardReference { Title = "Domain Name System", Reference = "RFC 1035", Url = "https://www.rfc-editor.org/rfc/rfc1035" },
            new StandardReference { Title = "Certification Authority Authorization (CAA) Resource Record", Reference = "RFC 8659", Url = "https://www.rfc-editor.org/rfc/rfc8659" }
        };

        var provider = analysis.Provider != DnsProvider.Unknown ? analysis.Provider.ToString() : "-";
        var mail = analysis.MailProvider != MailProviderKind.Unknown ? analysis.MailProvider.ToString() : "-";
        var cname = analysis.CnameTargetProvider != DnsCnameTargetProvider.Unknown ? analysis.CnameTargetProvider.ToString() : "-";
        var cnameService = analysis.CnameTargetService != DnsCnameTargetService.Unknown ? analysis.CnameTargetService.ToString() : "-";
        var txt = analysis.TxtSignals != DnsTxtSignals.None ? analysis.TxtSignals.ToString() : "-";
        var caa = analysis.CaaIssuers != DnsCaaIssuers.None ? analysis.CaaIssuers.ToString() : "-";
        var summary = $"{analysis.TotalRecords} record(s); types {analysis.RecordTypesQueried}; failed {analysis.RecordTypesFailed}; dns {provider}; mail {mail}; cname {cname}; cname-service {cnameService}; txt {txt}; apps {analysis.DetectedDnsApplications?.Count ?? 0}; caa {caa}; authority {(analysis.IncludeAuthorities ? "on" : "off")}; additional {(analysis.IncludeAdditional ? "on" : "off")}";

        return new DnsInventoryInfo
        {
            Check = HealthCheckType.DNSINVENTORY,
            Area = AreaForKind(HealthCheckType.DNSINVENTORY),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            FailureReason = analysis.FailureReason,
            RecordTypesQueried = analysis.RecordTypesQueried,
            RecordTypesFailed = analysis.RecordTypesFailed,
            TotalRecords = analysis.TotalRecords,
            Provider = analysis.Provider,
            ProviderScore = analysis.ProviderScore,
            ProviderEvidence = analysis.ProviderEvidence ?? Array.Empty<string>(),
            MailProvider = analysis.MailProvider,
            MailProviderScore = analysis.MailProviderScore,
            MailProviderEvidence = analysis.MailProviderEvidence ?? Array.Empty<string>(),
            CnameTargetProvider = analysis.CnameTargetProvider,
            CnameTargetService = analysis.CnameTargetService,
            CnameTargetFlags = analysis.CnameTargetFlags,
            CnameTargetEvidence = analysis.CnameTargetEvidence ?? Array.Empty<string>(),
            TxtSignals = analysis.TxtSignals,
            TxtSignalsEvidence = analysis.TxtSignalsEvidence ?? Array.Empty<string>(),
            DetectedDnsApplications = analysis.DetectedDnsApplications ?? Array.Empty<DetectedDnsApplication>(),
            CaaIssuers = analysis.CaaIssuers,
            CaaIssuersEvidence = analysis.CaaIssuersEvidence ?? Array.Empty<string>(),
            IncludeAuthorities = analysis.IncludeAuthorities,
            IncludeAdditional = analysis.IncludeAdditional,
            MaxRecordsPerSection = analysis.MaxRecordsPerSection,
            QueryConcurrency = analysis.QueryConcurrency,
            Queries = analysis.Queries ?? Array.Empty<DnsInventoryQuery>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(refs, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides dns inventory info functionality.</summary>
public sealed class DnsInventoryInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the record types queried value.</summary>
    public int RecordTypesQueried { get; set; }
    /// <summary>Gets or sets the record types failed value.</summary>
    public int RecordTypesFailed { get; set; }
    /// <summary>Gets or sets the total records value.</summary>
    public int TotalRecords { get; set; }
    /// <summary>Gets or sets the provider value.</summary>
    public DnsProvider Provider { get; set; }
    /// <summary>Gets or sets the provider score value.</summary>
    public int ProviderScore { get; set; }
    /// <summary>Gets or sets the provider evidence value.</summary>
    public IReadOnlyList<string> ProviderEvidence { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the mail provider value.</summary>
    public MailProviderKind MailProvider { get; set; }
    /// <summary>Gets or sets the mail provider score value.</summary>
    public int MailProviderScore { get; set; }
    /// <summary>Gets or sets the mail provider evidence value.</summary>
    public IReadOnlyList<string> MailProviderEvidence { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the cname target provider value.</summary>
    public DnsCnameTargetProvider CnameTargetProvider { get; set; }
    /// <summary>Gets or sets the specific CNAME target service value.</summary>
    public DnsCnameTargetService CnameTargetService { get; set; }
    /// <summary>Gets or sets the cname target flags value.</summary>
    public DnsCnameTargetFlags CnameTargetFlags { get; set; }
    /// <summary>Gets or sets the cname target evidence value.</summary>
    public IReadOnlyList<string> CnameTargetEvidence { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the txt signals value.</summary>
    public DnsTxtSignals TxtSignals { get; set; }
    /// <summary>Gets or sets the txt signals evidence value.</summary>
    public IReadOnlyList<string> TxtSignalsEvidence { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the detected dns applications value.</summary>
    public IReadOnlyList<DetectedDnsApplication> DetectedDnsApplications { get; set; } = Array.Empty<DetectedDnsApplication>();
    /// <summary>Gets or sets the caa issuers value.</summary>
    public DnsCaaIssuers CaaIssuers { get; set; }
    /// <summary>Gets or sets the caa issuers evidence value.</summary>
    public IReadOnlyList<string> CaaIssuersEvidence { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the include authorities value.</summary>
    public bool IncludeAuthorities { get; set; }
    /// <summary>Gets or sets the include additional value.</summary>
    public bool IncludeAdditional { get; set; }
    /// <summary>Gets or sets the max records per section value.</summary>
    public int MaxRecordsPerSection { get; set; }
    /// <summary>Gets or sets the query concurrency value.</summary>
    public int QueryConcurrency { get; set; }
    /// <summary>Gets or sets the queries value.</summary>
    public IReadOnlyList<DnsInventoryQuery> Queries { get; set; } = Array.Empty<DnsInventoryQuery>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public DnsInventoryAnalysis Raw { get; set; } = null!;
}
