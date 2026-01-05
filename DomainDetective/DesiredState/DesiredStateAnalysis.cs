using System.Collections.Generic;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

/// <summary>Stores desired state conformance results as structured assessments.</summary>
public sealed class DesiredStateAnalysis : IHasAssessments {
    /// <summary>Domain name the desired state evaluation applies to.</summary>
    public string? Subject { get; set; }

    /// <summary>Mail classification used when selecting the baseline (when available).</summary>
    public MailDomainClassificationCategory? MailClassification { get; set; }

    /// <summary>Indicates whether the domain conforms to the desired state baseline.</summary>
    public bool Conforms { get; set; }

    /// <summary>Structured assessments describing conformance and drift.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Actionable recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}

