using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class TtlInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool DnssecSigned { get; set; }
    public IReadOnlyList<int> ATtls { get; set; } = null!;
    public IReadOnlyList<int> AaaaTtls { get; set; } = null!;
    public IReadOnlyList<int> MxTtls { get; set; } = null!;
    public IReadOnlyList<int> NsTtls { get; set; } = null!;
    public int SoaTtl { get; set; }
    public IReadOnlyList<int> SpfTxtTtls { get; set; } = null!;
    public IReadOnlyList<int> DmarcTxtTtls { get; set; } = null!;
    public IReadOnlyList<int> MtastsTxtTtls { get; set; } = null!;
    public IReadOnlyList<int> TlsRptTxtTtls { get; set; } = null!;
    public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsTtlAnalysis Raw { get; set; } = null!;
}
