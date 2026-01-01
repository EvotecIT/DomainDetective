using System;
using System.Collections.Generic;
using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;

namespace DomainDetective.Views;

public static partial class Converters
{
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
        var txt = analysis.TxtSignals != DnsTxtSignals.None ? analysis.TxtSignals.ToString() : "-";
        var caa = analysis.CaaIssuers != DnsCaaIssuers.None ? analysis.CaaIssuers.ToString() : "-";
        var summary = $"{analysis.TotalRecords} record(s); types {analysis.RecordTypesQueried}; failed {analysis.RecordTypesFailed}; dns {provider}; mail {mail}; cname {cname}; txt {txt}; caa {caa}; authority {(analysis.IncludeAuthorities ? "on" : "off")}; additional {(analysis.IncludeAdditional ? "on" : "off")}";

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
            CnameTargetFlags = analysis.CnameTargetFlags,
            CnameTargetEvidence = analysis.CnameTargetEvidence ?? Array.Empty<string>(),
            TxtSignals = analysis.TxtSignals,
            TxtSignalsEvidence = analysis.TxtSignalsEvidence ?? Array.Empty<string>(),
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

public sealed class DnsInventoryInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool QuerySucceeded { get; set; }
    public string? FailureReason { get; set; }
    public int RecordTypesQueried { get; set; }
    public int RecordTypesFailed { get; set; }
    public int TotalRecords { get; set; }
    public DnsProvider Provider { get; set; }
    public int ProviderScore { get; set; }
    public IReadOnlyList<string> ProviderEvidence { get; set; } = null!;
    public MailProviderKind MailProvider { get; set; }
    public int MailProviderScore { get; set; }
    public IReadOnlyList<string> MailProviderEvidence { get; set; } = null!;
    public DnsCnameTargetProvider CnameTargetProvider { get; set; }
    public DnsCnameTargetFlags CnameTargetFlags { get; set; }
    public IReadOnlyList<string> CnameTargetEvidence { get; set; } = null!;
    public DnsTxtSignals TxtSignals { get; set; }
    public IReadOnlyList<string> TxtSignalsEvidence { get; set; } = null!;
    public DnsCaaIssuers CaaIssuers { get; set; }
    public IReadOnlyList<string> CaaIssuersEvidence { get; set; } = null!;
    public bool IncludeAuthorities { get; set; }
    public bool IncludeAdditional { get; set; }
    public int MaxRecordsPerSection { get; set; }
    public int QueryConcurrency { get; set; }
    public IReadOnlyList<DnsInventoryQuery> Queries { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsInventoryAnalysis Raw { get; set; } = null!;
}
