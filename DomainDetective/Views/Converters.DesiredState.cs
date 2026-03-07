using System.Linq;
using DomainDetective;
using DomainDetective.DesiredState;
using DomainDetective.Definitions;

namespace DomainDetective.Views;

public static partial class Converters {
    public static DesiredStateInfo Convert(DesiredStateAnalysis analysis, DesiredStateProfile? profile = null, DesiredStateMode mode = DesiredStateMode.HybridSplit) {
        if (analysis == null) {
            throw new System.ArgumentNullException(nameof(analysis));
        }

        var split = DesiredStateAssessmentSplitter.Split(analysis, profile, mode);
        var desiredProblems = RecommendationEngine.FromProblems(split.DesiredAssessments);
        var desiredPositives = RecommendationEngine.FromPositives(split.DesiredAssessments);
        var bestProblems = RecommendationEngine.FromProblems(split.BestPracticeAssessments);
        var bestPositives = RecommendationEngine.FromPositives(split.BestPracticeAssessments);

        var references = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        void CollectLinks(System.Collections.Generic.IReadOnlyList<RecommendationAdvice> recs) {
            if (recs == null) return;
            foreach (var r in recs) {
                if (r?.Links == null) continue;
                foreach (var l in r.Links) {
                    if (!string.IsNullOrWhiteSpace(l)) references.Add(l);
                }
            }
        }
        CollectLinks(desiredProblems);
        CollectLinks(desiredPositives);
        CollectLinks(bestProblems);
        CollectLinks(bestPositives);

        return new DesiredStateInfo {
            Subject = analysis.Subject,
            MailClassification = analysis.MailClassification ?? MailDomainClassificationCategory.Unknown,
            Mode = mode,
            Conforms = split.Conforms,
            TotalAssessments = split.DesiredAssessments.Count,
            InfoCount = split.DesiredInfoCount,
            WarningCount = split.DesiredWarningCount,
            ErrorCount = split.DesiredErrorCount,
            BestPracticeTotalAssessments = split.BestPracticeAssessments.Count,
            BestPracticeInfoCount = split.BestPracticeInfoCount,
            BestPracticeWarningCount = split.BestPracticeWarningCount,
            BestPracticeErrorCount = split.BestPracticeErrorCount,
            Recommendations = desiredProblems,
            Positives = desiredPositives,
            BestPracticeRecommendations = bestProblems,
            BestPracticePositives = bestPositives,
            DesiredAssessments = split.DesiredAssessments,
            BestPracticeAssessments = split.BestPracticeAssessments,
            References = references.ToList(),
            Raw = analysis
        };
    }
}

public sealed class DesiredStateInfo {
    public string? Subject { get; set; }

    public MailDomainClassificationCategory MailClassification { get; set; }

    public DesiredStateMode Mode { get; set; } = DesiredStateMode.HybridSplit;

    public bool Conforms { get; set; }

    public int TotalAssessments { get; set; }

    public int InfoCount { get; set; }

    public int WarningCount { get; set; }

    public int ErrorCount { get; set; }

    public int BestPracticeTotalAssessments { get; set; }

    public int BestPracticeInfoCount { get; set; }

    public int BestPracticeWarningCount { get; set; }

    public int BestPracticeErrorCount { get; set; }

    public System.Collections.Generic.IReadOnlyList<Assessment> DesiredAssessments { get; set; } = System.Array.Empty<Assessment>();

    public System.Collections.Generic.IReadOnlyList<Assessment> BestPracticeAssessments { get; set; } = System.Array.Empty<Assessment>();

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> BestPracticeRecommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> BestPracticePositives { get; set; } = System.Array.Empty<RecommendationAdvice>();

    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();

    public string SectionKey { get; set; } = "Desired State";

    public DesiredStateAnalysis Raw { get; set; } = null!;
}
