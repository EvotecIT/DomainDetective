using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

/// <summary>Provides converters functionality.</summary>
public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
    /// <summary>Gets or sets the has a record value.</summary>
    public bool HasARecord { get; set; }
    /// <summary>Gets or sets the has aaaa record value.</summary>
    public bool HasAaaaRecord { get; set; }
    /// <summary>Gets or sets the has any address value.</summary>
    public bool HasAnyAddress { get; set; }
    /// <summary>Gets or sets the i pv4 count value.</summary>
    public int IPv4Count { get; set; }
    /// <summary>Gets or sets the i pv6 count value.</summary>
    public int IPv6Count { get; set; }
    /// <summary>Gets or sets the distinct subnet count v4 value.</summary>
    public int DistinctSubnetCountV4 { get; set; }
    /// <summary>Gets or sets the distinct subnet count v6 value.</summary>
    public int DistinctSubnetCountV6 { get; set; }
    /// <summary>Gets or sets the private address count value.</summary>
    public int PrivateAddressCount { get; set; }
    /// <summary>Gets or sets the loopback count value.</summary>
    public int LoopbackCount { get; set; }
    /// <summary>Gets or sets the link local count value.</summary>
    public int LinkLocalCount { get; set; }
    /// <summary>Gets or sets the multicast count value.</summary>
    public int MulticastCount { get; set; }
    /// <summary>Gets or sets the documentation address count value.</summary>
    public int DocumentationAddressCount { get; set; }
    /// <summary>Gets or sets the unique local v6 count value.</summary>
    public int UniqueLocalV6Count { get; set; }
    /// <summary>Gets or sets the public address count value.</summary>
    public int PublicAddressCount { get; set; }
    /// <summary>PTR hostnames observed per IP.</summary>
    public IReadOnlyDictionary<string, List<string>> PtrByIp { get; set; } = new System.Collections.Generic.Dictionary<string, List<string>>();
    /// <summary>Gets or sets the any ptr present value.</summary>
    public bool AnyPtrPresent { get; set; }
    /// <summary>Gets or sets the all ptr present value.</summary>
    public bool AllPtrPresent { get; set; }
    /// <summary>Gets or sets the fcr dns valid count value.</summary>
    public int FcrDnsValidCount { get; set; }
    /// <summary>Gets or sets the all fcr dns valid value.</summary>
    public bool AllFcrDnsValid { get; set; }
    /// <summary>ASN mapping per IP.</summary>
    public IReadOnlyDictionary<string, int> AsnByIp { get; set; } = new System.Collections.Generic.Dictionary<string, int>();
    /// <summary>Gets or sets the asn distinct count value.</summary>
    public int AsnDistinctCount { get; set; }
    /// <summary>Gets or sets the rpki valid count value.</summary>
    public int RpkiValidCount { get; set; }
    /// <summary>Gets or sets the all rpki valid value.</summary>
    public bool AllRpkiValid { get; set; }
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
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
