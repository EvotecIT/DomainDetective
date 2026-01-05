using System.Linq;
using DomainDetective.DesiredState;
using DomainDetective.Definitions;

namespace DomainDetective.Views;

public static partial class Converters {
    public static DesiredStateInfo Convert(DesiredStateAnalysis analysis) {
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var problems = RecommendationEngine.FromProblems(analysis.Assessments);

        int info = 0, warn = 0, err = 0;
        foreach (var a in analysis.Assessments) {
            switch (a.Severity) {
                case AssessmentSeverity.Info: info++; break;
                case AssessmentSeverity.Warning: warn++; break;
                case AssessmentSeverity.Error: err++; break;
            }
        }

        return new DesiredStateInfo {
            Subject = analysis.Subject,
            MailClassification = analysis.MailClassification ?? MailDomainClassificationCategory.Unknown,
            Conforms = analysis.Conforms,
            TotalAssessments = info + warn + err,
            InfoCount = info,
            WarningCount = warn,
            ErrorCount = err,
            Recommendations = problems,
            Positives = positives,
            Raw = analysis
        };
    }
}

public sealed class DesiredStateInfo {
    public string? Subject { get; set; }

    public MailDomainClassificationCategory MailClassification { get; set; }

    public bool Conforms { get; set; }

    public int TotalAssessments { get; set; }

    public int InfoCount { get; set; }

    public int WarningCount { get; set; }

    public int ErrorCount { get; set; }

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public DesiredStateAnalysis Raw { get; set; } = null!;
}

