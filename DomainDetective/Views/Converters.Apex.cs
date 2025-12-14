using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ApexAddressInfo Convert(ApexAddressAnalysis analysis)
    {
        var assessments = new List<Assessment>();
        var recs = RecommendationEngine.FromProblems(assessments);
        // ApexAddressAnalysis currently does not implement IHasAssessments; derive status from address quality flags
        int warnCount = 0, errCount = 0;
        string status = (analysis.HasAnyAddress ? "OK" : "Warning");
        if (!analysis.HasAnyAddress) warnCount = 1;

        return new ApexAddressInfo
        {
            Check = HealthCheckType.APEXADDRESS,
            Area = AreaForKind(HealthCheckType.APEXADDRESS),
            Subject = analysis.Subject ?? string.Empty,
            ARecords = analysis.ARecords,
            AaaaRecords = analysis.AaaaRecords,
            HasARecord = analysis.HasARecord,
            HasAaaaRecord = analysis.HasAaaaRecord,
            HasAnyAddress = analysis.HasAnyAddress,
            IPv4Count = analysis.IPv4Count,
            IPv6Count = analysis.IPv6Count,
            DistinctSubnetCountV4 = analysis.DistinctSubnetCountV4,
            DistinctSubnetCountV6 = analysis.DistinctSubnetCountV6,
            PrivateAddressCount = analysis.PrivateAddressCount,
            LoopbackCount = analysis.LoopbackCount,
            LinkLocalCount = analysis.LinkLocalCount,
            MulticastCount = analysis.MulticastCount,
            DocumentationAddressCount = analysis.DocumentationAddressCount,
            UniqueLocalV6Count = analysis.UniqueLocalV6Count,
            PublicAddressCount = analysis.PublicAddressCount,
            PtrByIp = analysis.PtrByIp,
            AnyPtrPresent = analysis.AnyPtrPresent,
            AllPtrPresent = analysis.AllPtrPresent,
            FcrDnsValidCount = analysis.FcrDnsValidCount,
            AllFcrDnsValid = analysis.AllFcrDnsValid,
            AsnByIp = analysis.AsnByIp,
            AsnDistinctCount = analysis.AsnDistinctCount,
            RpkiValidCount = analysis.RpkiValidCount,
            AllRpkiValid = analysis.AllRpkiValid,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"A {analysis.IPv4Count}, AAAA {analysis.IPv6Count}; FCrDNS {(analysis.AllFcrDnsValid ? "ok" : "check")}",
            Recommendations = recs,
            Positives = RecommendationEngine.FromPositives(assessments),
            References = BuildReferences(analysis.RfcReferences.ToArray(), recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing apex A/AAAA address posture and reverse-DNS/RPKI signals.
/// </summary>
public class ApexAddressInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>A records at the apex.</summary>
    public IReadOnlyList<string> ARecords { get; set; } = System.Array.Empty<string>();
    /// <summary>AAAA records at the apex.</summary>
    public IReadOnlyList<string> AaaaRecords { get; set; } = System.Array.Empty<string>();
    public bool HasARecord { get; set; }
    public bool HasAaaaRecord { get; set; }
    public bool HasAnyAddress { get; set; }
    public int IPv4Count { get; set; }
    public int IPv6Count { get; set; }
    public int DistinctSubnetCountV4 { get; set; }
    public int DistinctSubnetCountV6 { get; set; }
    public int PrivateAddressCount { get; set; }
    public int LoopbackCount { get; set; }
    public int LinkLocalCount { get; set; }
    public int MulticastCount { get; set; }
    public int DocumentationAddressCount { get; set; }
    public int UniqueLocalV6Count { get; set; }
    public int PublicAddressCount { get; set; }
    /// <summary>PTR hostnames observed per IP.</summary>
    public IReadOnlyDictionary<string, List<string>> PtrByIp { get; set; } = new System.Collections.Generic.Dictionary<string, List<string>>();
    public bool AnyPtrPresent { get; set; }
    public bool AllPtrPresent { get; set; }
    public int FcrDnsValidCount { get; set; }
    public bool AllFcrDnsValid { get; set; }
    /// <summary>ASN mapping per IP.</summary>
    public IReadOnlyDictionary<string, int> AsnByIp { get; set; } = new System.Collections.Generic.Dictionary<string, int>();
    public int AsnDistinctCount { get; set; }
    public int RpkiValidCount { get; set; }
    public bool AllRpkiValid { get; set; }
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    /// <summary>Short summary text used in executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public ApexAddressAnalysis Raw { get; set; } = new ApexAddressAnalysis();
}
