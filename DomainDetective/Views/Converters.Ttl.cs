using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static TtlInfo Convert(DnsTtlAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
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
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"SOA {analysis.SoaTtl}s; A min/max {(analysis.ATtls?.Count>0?System.Math.Min(int.MaxValue, analysis.ATtls.Min()).ToString():"-")}/{(analysis.ATtls?.Count>0?analysis.ATtls.Max().ToString():"-")}",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Raw = analysis
        };
    }
}

public class TtlInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public bool DnssecSigned { get; set; }
    public IReadOnlyList<int> ATtls { get; set; }
    public IReadOnlyList<int> AaaaTtls { get; set; }
    public IReadOnlyList<int> MxTtls { get; set; }
    public IReadOnlyList<int> NsTtls { get; set; }
    public int SoaTtl { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DnsTtlAnalysis Raw { get; set; }
}
