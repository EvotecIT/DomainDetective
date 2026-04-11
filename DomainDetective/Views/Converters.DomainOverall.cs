using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides domain overall info functionality.</summary>
public sealed class DomainOverallInfo
{
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public DomainSummary Summary { get; set; } = null!;
    /// <summary>Gets or sets the total assessments value.</summary>
    public int TotalAssessments { get; set; }
    /// <summary>Gets or sets the info count value.</summary>
    public int InfoCount { get; set; }
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationView> Recommendations { get; set; } = System.Array.Empty<RecommendationView>();
    /// <summary>Gets or sets the raw value.</summary>
    public DomainHealthCheck Raw { get; set; } = null!;
}
