using System.Linq;
using DomainDetective;
using DomainDetective.DesiredState;
using DomainDetective.Definitions;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides desired state info functionality.</summary>
public sealed class DesiredStateInfo {
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }

    /// <summary>Gets or sets the mail classification value.</summary>
    public MailDomainClassificationCategory MailClassification { get; set; }

    /// <summary>Gets or sets the mode value.</summary>
    public DesiredStateMode Mode { get; set; } = DesiredStateMode.HybridSplit;

    /// <summary>Gets or sets the conforms value.</summary>
    public bool Conforms { get; set; }

    /// <summary>Gets or sets the total assessments value.</summary>
    public int TotalAssessments { get; set; }

    /// <summary>Gets or sets the info count value.</summary>
    public int InfoCount { get; set; }

    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }

    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }

    /// <summary>Gets or sets the best practice total assessments value.</summary>
    public int BestPracticeTotalAssessments { get; set; }

    /// <summary>Gets or sets the best practice info count value.</summary>
    public int BestPracticeInfoCount { get; set; }

    /// <summary>Gets or sets the best practice warning count value.</summary>
    public int BestPracticeWarningCount { get; set; }

    /// <summary>Gets or sets the best practice error count value.</summary>
    public int BestPracticeErrorCount { get; set; }

    /// <summary>Gets or sets the desired assessments value.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> DesiredAssessments { get; set; } = System.Array.Empty<Assessment>();

    /// <summary>Gets or sets the best practice assessments value.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> BestPracticeAssessments { get; set; } = System.Array.Empty<Assessment>();

    /// <summary>Gets or sets the recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();

    /// <summary>Gets or sets the positives value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();

    /// <summary>Gets or sets the best practice recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> BestPracticeRecommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();

    /// <summary>Gets or sets the best practice positives value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> BestPracticePositives { get; set; } = System.Array.Empty<RecommendationAdvice>();

    /// <summary>Gets or sets the references value.</summary>
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();

    /// <summary>Gets or sets the section key value.</summary>
    public string SectionKey { get; set; } = "Desired State";

    /// <summary>Gets or sets the raw value.</summary>
    public DesiredStateAnalysis Raw { get; set; } = null!;
}
