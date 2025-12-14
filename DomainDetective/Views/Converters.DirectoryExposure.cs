using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DirectoryExposureInfo Convert(DirectoryExposureAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
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
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class DirectoryExposureInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int ExposedCount { get; set; }
    public IReadOnlyList<string> ExposedPaths { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DirectoryExposureAnalysis Raw { get; set; } = null!;
}
