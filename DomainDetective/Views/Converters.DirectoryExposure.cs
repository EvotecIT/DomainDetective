using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DirectoryExposureInfo Convert(DirectoryExposureAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new DirectoryExposureInfo
        {
            Check = HealthCheckType.DIRECTORYEXPOSURE,
            Area = AreaForKind(HealthCheckType.DIRECTORYEXPOSURE),
            Subject = analysis.Subject,
            ExposedPaths = analysis.ExposedPaths,
            ExposedCount = analysis.ExposedPaths?.Count ?? 0,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"exposed {analysis.ExposedPaths?.Count ?? 0} paths",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class DirectoryExposureInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int ExposedCount { get; set; }
    public IReadOnlyList<string> ExposedPaths { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DirectoryExposureAnalysis Raw { get; set; }
}
