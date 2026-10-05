using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
            SoaSerialConsistency = analysis.SoaSerialConsistency,
            ApexAddressesConsistency = analysis.ApexAddressesConsistency,
            ProbeResults = analysis.ProbeResults,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = $"SOA: {analysis.SoaSerialConsistency}; Apex: {analysis.ApexAddressesConsistency}; responded: {analysis.ProbeResults.FindAll(probe => probe.HasResponse).Count}/{analysis.ProbeResults.Count}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides dns health info functionality.</summary>
public class DnsHealthInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the name servers value.</summary>
    public IReadOnlyList<string> NameServers { get; set; } = null!;
    /// <summary>Gets or sets the soa serial by server value.</summary>
    public IReadOnlyDictionary<string, long> SoaSerialByServer { get; set; } = null!;
    /// <summary>Gets or sets the soa serial consistent value.</summary>
    public bool SoaSerialConsistent { get; set; }
    /// <summary>Gets or sets the apex addresses by server value.</summary>
    public IReadOnlyDictionary<string, List<string>> ApexAddressesByServer { get; set; } = null!;
    /// <summary>Gets or sets the apex addresses consistent value.</summary>
    public bool ApexAddressesConsistent { get; set; }
    /// <summary>Gets or sets the servers responsive value.</summary>
    public bool ServersResponsive { get; set; }
    /// <summary>Gets or sets the SOA comparison conclusion, including insufficient evidence.</summary>
    public DnsHealthConsistencyStatus SoaSerialConsistency { get; set; }
    /// <summary>Gets or sets the apex comparison conclusion, including insufficient evidence.</summary>
    public DnsHealthConsistencyStatus ApexAddressesConsistency { get; set; }
    /// <summary>Gets or sets per-address query coverage and response diagnostics.</summary>
    public IReadOnlyList<DnsHealthProbeResult> ProbeResults { get; set; } = System.Array.Empty<DnsHealthProbeResult>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public DnsHealthAnalysis Raw { get; set; } = null!;
}
