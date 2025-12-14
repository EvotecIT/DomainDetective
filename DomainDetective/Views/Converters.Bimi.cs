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
            Subject = analysis.Subject ?? string.Empty,
            BimiRecord = analysis.BimiRecord ?? string.Empty,
            BimiRecordExists = analysis.BimiRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            Location = analysis.Location ?? string.Empty,
            Authority = analysis.Authority ?? string.Empty,
            LocationUsesHttps = analysis.LocationUsesHttps,
            AuthorityUsesHttps = analysis.AuthorityUsesHttps,
            DeclinedToPublish = analysis.DeclinedToPublish,
            InvalidLocation = analysis.InvalidLocation,
            SvgFetched = analysis.SvgFetched,
            SvgValid = analysis.SvgValid,
            SvgInvalidReason = analysis.SvgInvalidReason ?? string.Empty,
            SvgSizeValid = analysis.SvgSizeValid,
            DimensionsValid = analysis.DimensionsValid,
            ViewBoxValid = analysis.ViewBoxValid,
            SvgAttributesPresent = analysis.SvgAttributesPresent,
            ValidVmc = analysis.ValidVmc,
            VmcSignedByKnownRoot = analysis.VmcSignedByKnownRoot,
            VmcContainsLogo = analysis.VmcContainsLogo,
            FailureReason = analysis.FailureReason ?? string.Empty,
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

/// <summary>
/// View model summarizing BIMI (Brand Indicators for Message Identification) analysis.
/// </summary>
public class BimiRecordInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Raw BIMI TXT record.</summary>
    public string BimiRecord { get; set; } = string.Empty;
    public bool BimiRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    /// <summary>URL to the SVG indicator (l=).</summary>
    public string Location { get; set; } = string.Empty;
    /// <summary>URL to the VMC certificate (a=).</summary>
    public string Authority { get; set; } = string.Empty;
    public bool LocationUsesHttps { get; set; }
    public bool AuthorityUsesHttps { get; set; }
    public bool DeclinedToPublish { get; set; }
    public bool InvalidLocation { get; set; }
    public bool SvgFetched { get; set; }
    public bool SvgValid { get; set; }
    /// <summary>Why the SVG failed validation (when invalid).</summary>
    public string SvgInvalidReason { get; set; } = string.Empty;
    public bool SvgSizeValid { get; set; }
    public bool DimensionsValid { get; set; }
    public bool ViewBoxValid { get; set; }
    public bool SvgAttributesPresent { get; set; }
    public bool ValidVmc { get; set; }
    public bool VmcSignedByKnownRoot { get; set; }
    public bool VmcContainsLogo { get; set; }
    /// <summary>Failure reason when HTTP requests fail.</summary>
    public string FailureReason { get; set; } = string.Empty;
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
    public BimiAnalysis Raw { get; set; } = new BimiAnalysis();
}
