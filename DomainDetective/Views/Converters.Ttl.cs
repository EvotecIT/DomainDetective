using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static TtlInfo Convert(DnsTtlAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new TtlInfo
        {
            Check = HealthCheckType.TTL,
            Area = AreaForKind(HealthCheckType.TTL),
            Subject = analysis.Subject,
            DnssecSigned = analysis.DnsSecSigned,
            ATtls = analysis.ATtls,
            AaaaTtls = analysis.AaaaTtls,
            MxTtls = analysis.MxTtls,
            NsTtls = analysis.NsTtls,
            SoaTtl = analysis.SoaTtl,
            SpfTxtTtls = analysis.SpfTxtTtls,
            DmarcTxtTtls = analysis.DmarcTxtTtls,
            MtastsTxtTtls = analysis.MtastsTxtTtls,
            TlsRptTxtTtls = analysis.TlsRptTxtTtls,
            DkimTxtTtls = analysis.DkimTxtTtls,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"SOA {analysis.SoaTtl}s; A min/max {(analysis.ATtls?.Count>0?System.Math.Min(int.MaxValue, analysis.ATtls.Min()).ToString():"-")}/{(analysis.ATtls?.Count>0?analysis.ATtls.Max().ToString():"-")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Raw = analysis
        };
    }
}

/// <summary>Provides ttl info functionality.</summary>
public class TtlInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the dnssec signed value.</summary>
    public bool DnssecSigned { get; set; }
    /// <summary>Gets or sets the a ttls value.</summary>
    public IReadOnlyList<int> ATtls { get; set; } = null!;
    /// <summary>Gets or sets the aaaa ttls value.</summary>
    public IReadOnlyList<int> AaaaTtls { get; set; } = null!;
    /// <summary>Gets or sets the mx ttls value.</summary>
    public IReadOnlyList<int> MxTtls { get; set; } = null!;
    /// <summary>Gets or sets the ns ttls value.</summary>
    public IReadOnlyList<int> NsTtls { get; set; } = null!;
    /// <summary>Gets or sets the soa ttl value.</summary>
    public int SoaTtl { get; set; }
    /// <summary>Gets or sets the spf txt ttls value.</summary>
    public IReadOnlyList<int> SpfTxtTtls { get; set; } = null!;
    /// <summary>Gets or sets the dmarc txt ttls value.</summary>
    public IReadOnlyList<int> DmarcTxtTtls { get; set; } = null!;
    /// <summary>Gets or sets the mtasts txt ttls value.</summary>
    public IReadOnlyList<int> MtastsTxtTtls { get; set; } = null!;
    /// <summary>Gets or sets the tls rpt txt ttls value.</summary>
    public IReadOnlyList<int> TlsRptTxtTtls { get; set; } = null!;
    /// <summary>Gets or sets the dkim txt ttls value.</summary>
    public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; set; } = null!;
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
    public DnsTtlAnalysis Raw { get; set; } = null!;
}
