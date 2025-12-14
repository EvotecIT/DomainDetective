using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DomainOverallInfo Convert(DomainHealthCheck health, string subject)
    {
        var summary = health.BuildSummary();
        int info = 0, warn = 0, err = 0;
        foreach (var a in health.GetAllAssessments())
        {
            switch (a.Severity)
            {
                case AssessmentSeverity.Info: info++; break;
                case AssessmentSeverity.Warning: warn++; break;
                case AssessmentSeverity.Error: err++; break;
            }
        }

        return new DomainOverallInfo
        {
            Subject = subject,
            Summary = summary,
            TotalAssessments = info + warn + err,
            InfoCount = info,
            WarningCount = warn,
            ErrorCount = err,
            Recommendations = health.RecommendationViews ?? System.Array.Empty<RecommendationView>(),
            Raw = health
        };
    }
}

public sealed class DomainOverallInfo
{
    public string? Subject { get; set; }
    public DomainSummary Summary { get; set; } = null!;
    public int TotalAssessments { get; set; }
    public int InfoCount { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public System.Collections.Generic.IReadOnlyList<RecommendationView> Recommendations { get; set; } = System.Array.Empty<RecommendationView>();
    public DomainHealthCheck Raw { get; set; } = null!;
}
