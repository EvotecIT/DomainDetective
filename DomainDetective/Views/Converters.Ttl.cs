using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static TtlInfo Convert(DnsTtlAnalysis analysis)
    {
        static IReadOnlyList<int> PreferAuthoritative(IReadOnlyList<int> authoritative, IReadOnlyList<int> observed) =>
            authoritative != null && authoritative.Count > 0 ? authoritative : observed ?? System.Array.Empty<int>();
        static Dictionary<string, IReadOnlyList<int>> PreferAuthoritativeMap(Dictionary<string, IReadOnlyList<int>> authoritative, Dictionary<string, IReadOnlyList<int>> observed)
        {
            if (authoritative != null && authoritative.Count > 0)
            {
                return authoritative;
            }

            return observed ?? new Dictionary<string, IReadOnlyList<int>>();
        }

        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var aTtls = PreferAuthoritative(analysis.AuthoritativeATtls, analysis.ATtls);
        var aaaaTtls = PreferAuthoritative(analysis.AuthoritativeAaaaTtls, analysis.AaaaTtls);
        var mxTtls = PreferAuthoritative(analysis.AuthoritativeMxTtls, analysis.MxTtls);
        var nsTtls = PreferAuthoritative(analysis.AuthoritativeNsTtls, analysis.NsTtls);
        var spfTtls = PreferAuthoritative(analysis.AuthoritativeSpfTxtTtls, analysis.SpfTxtTtls);
        var dmarcTtls = PreferAuthoritative(analysis.AuthoritativeDmarcTxtTtls, analysis.DmarcTxtTtls);
        var mtastsTtls = PreferAuthoritative(analysis.AuthoritativeMtastsTxtTtls, analysis.MtastsTxtTtls);
        var tlsRptTtls = PreferAuthoritative(analysis.AuthoritativeTlsRptTxtTtls, analysis.TlsRptTxtTtls);
        var dkimMap = PreferAuthoritativeMap(analysis.AuthoritativeDkimTxtTtls, analysis.DkimTxtTtls);
        var soaEffective = analysis.AuthoritativeSoaTtl ?? analysis.SoaTtl;
        return new TtlInfo
        {
            Check = HealthCheckType.TTL,
            Area = AreaForKind(HealthCheckType.TTL),
            Subject = analysis.Subject,
            DnssecSigned = analysis.DnsSecSigned,
            ATtls = aTtls,
            AuthoritativeATtls = analysis.AuthoritativeATtls,
            AaaaTtls = aaaaTtls,
            AuthoritativeAaaaTtls = analysis.AuthoritativeAaaaTtls,
            MxTtls = mxTtls,
            AuthoritativeMxTtls = analysis.AuthoritativeMxTtls,
            NsTtls = nsTtls,
            AuthoritativeNsTtls = analysis.AuthoritativeNsTtls,
            SoaTtl = soaEffective,
            AuthoritativeSoaTtl = analysis.AuthoritativeSoaTtl,
            SpfTxtTtls = spfTtls,
            AuthoritativeSpfTxtTtls = analysis.AuthoritativeSpfTxtTtls,
            DmarcTxtTtls = dmarcTtls,
            AuthoritativeDmarcTxtTtls = analysis.AuthoritativeDmarcTxtTtls,
            MtastsTxtTtls = mtastsTtls,
            AuthoritativeMtastsTxtTtls = analysis.AuthoritativeMtastsTxtTtls,
            TlsRptTxtTtls = tlsRptTtls,
            AuthoritativeTlsRptTxtTtls = analysis.AuthoritativeTlsRptTxtTtls,
            DkimTxtTtls = dkimMap,
            AuthoritativeDkimTxtTtls = analysis.AuthoritativeDkimTxtTtls,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"SOA {soaEffective}s; A min/max {(aTtls?.Count>0?System.Math.Min(int.MaxValue, aTtls.Min()).ToString():"-")}/{(aTtls?.Count>0?aTtls.Max().ToString():"-")}",
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
    public string Subject { get; set; }
    public bool DnssecSigned { get; set; }
    public IReadOnlyList<int> ATtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeATtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AaaaTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeAaaaTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> MxTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeMxTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> NsTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeNsTtls { get; set; } = System.Array.Empty<int>();
    public int SoaTtl { get; set; }
    public int? AuthoritativeSoaTtl { get; set; }
    public IReadOnlyList<int> SpfTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeSpfTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> DmarcTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeDmarcTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> MtastsTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeMtastsTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> TlsRptTxtTtls { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<int> AuthoritativeTlsRptTxtTtls { get; set; } = System.Array.Empty<int>();
    public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; set; } = new();
    public Dictionary<string, IReadOnlyList<int>> AuthoritativeDkimTxtTtls { get; set; } = new();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DnsTtlAnalysis Raw { get; set; } = new DnsTtlAnalysis();
}
