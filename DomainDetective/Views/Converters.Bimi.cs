using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static BimiRecordInfo Convert(BimiAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        return new BimiRecordInfo
        {
            Check = HealthCheckType.BIMI,
            Area = AreaForKind(HealthCheckType.BIMI),
            Subject = analysis.Subject,
            BimiRecord = analysis.BimiRecord,
            BimiRecordExists = analysis.BimiRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            Location = analysis.Location,
            Authority = analysis.Authority,
            LocationUsesHttps = analysis.LocationUsesHttps,
            AuthorityUsesHttps = analysis.AuthorityUsesHttps,
            DeclinedToPublish = analysis.DeclinedToPublish,
            InvalidLocation = analysis.InvalidLocation,
            SvgFetched = analysis.SvgFetched,
            SvgValid = analysis.SvgValid,
            SvgInvalidReason = analysis.SvgInvalidReason,
            SvgSizeValid = analysis.SvgSizeValid,
            DimensionsValid = analysis.DimensionsValid,
            ViewBoxValid = analysis.ViewBoxValid,
            SvgAttributesPresent = analysis.SvgAttributesPresent,
            ValidVmc = analysis.ValidVmc,
            VmcSignedByKnownRoot = analysis.VmcSignedByKnownRoot,
            VmcContainsLogo = analysis.VmcContainsLogo,
            FailureReason = analysis.FailureReason,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"svg {(analysis.SvgValid ? "ok" : "invalid")}; vmc {(analysis.ValidVmc ? "ok" : "missing")}; https {(analysis.LocationUsesHttps ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class BimiRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string BimiRecord { get; set; } = string.Empty;
    public bool BimiRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public string Location { get; set; } = string.Empty;
    public string Authority { get; set; } = string.Empty;
    public bool LocationUsesHttps { get; set; }
    public bool AuthorityUsesHttps { get; set; }
    public bool DeclinedToPublish { get; set; }
    public bool InvalidLocation { get; set; }
    public bool SvgFetched { get; set; }
    public bool SvgValid { get; set; }
    public string SvgInvalidReason { get; set; } = string.Empty;
    public bool SvgSizeValid { get; set; }
    public bool DimensionsValid { get; set; }
    public bool ViewBoxValid { get; set; }
    public bool SvgAttributesPresent { get; set; }
    public bool ValidVmc { get; set; }
    public bool VmcSignedByKnownRoot { get; set; }
    public bool VmcContainsLogo { get; set; }
    public string FailureReason { get; set; } = string.Empty;
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public BimiAnalysis Raw { get; set; } = new BimiAnalysis();
}
