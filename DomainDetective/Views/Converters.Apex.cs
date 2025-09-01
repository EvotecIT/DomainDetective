using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ApexAddressInfo Convert(ApexAddressAnalysis analysis)
    {
        var assessments = new List<Assessment>();
        // ApexAddressAnalysis currently does not implement IHasAssessments; derive status from address quality flags
        int warnCount = 0, errCount = 0;
        string status = (analysis.HasAnyAddress ? "OK" : "Warning");
        if (!analysis.HasAnyAddress) warnCount = 1;

        return new ApexAddressInfo
        {
            Check = "APEX",
            Area = AreaFor("APEX"),
            Subject = null,
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
            Recommendations = RecommendationEngine.From(assessments),
            References = BuildReferences(analysis.RfcReferences.ToArray(), RecommendationEngine.From(assessments)),
            Raw = analysis
        };
    }
}

public class ApexAddressInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<string> ARecords { get; set; }
    public IReadOnlyList<string> AaaaRecords { get; set; }
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
    public IReadOnlyDictionary<string, List<string>> PtrByIp { get; set; }
    public bool AnyPtrPresent { get; set; }
    public bool AllPtrPresent { get; set; }
    public int FcrDnsValidCount { get; set; }
    public bool AllFcrDnsValid { get; set; }
    public IReadOnlyDictionary<string, int> AsnByIp { get; set; }
    public int AsnDistinctCount { get; set; }
    public int RpkiValidCount { get; set; }
    public bool AllRpkiValid { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ApexAddressAnalysis Raw { get; set; }
}
