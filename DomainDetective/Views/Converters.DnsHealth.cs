using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsHealthInfo Convert(DnsHealthAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new DnsHealthInfo
        {
            Check = HealthCheckType.DNSHEALTH,
            Area = AnalysisArea.DNS,
            Subject = analysis.Subject,
            NameServers = analysis.NameServers,
            SoaSerialByServer = analysis.SoaSerialByServer,
            SoaSerialConsistent = analysis.SoaSerialConsistent,
            ApexAddressesByServer = analysis.ApexAddressesByServer,
            ApexAddressesConsistent = analysis.ApexAddressesConsistent,
            ServersResponsive = analysis.ServersResponsive,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = $"SOA consistent: {analysis.SoaSerialConsistent}; Apex consistent: {analysis.ApexAddressesConsistent}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class DnsHealthInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public IReadOnlyList<string> NameServers { get; set; } = null!;
    public IReadOnlyDictionary<string, long> SoaSerialByServer { get; set; } = null!;
    public bool SoaSerialConsistent { get; set; }
    public IReadOnlyDictionary<string, List<string>> ApexAddressesByServer { get; set; } = null!;
    public bool ApexAddressesConsistent { get; set; }
    public bool ServersResponsive { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsHealthAnalysis Raw { get; set; } = null!;
}
