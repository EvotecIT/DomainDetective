using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Aggregates multiple DNS propagation analyses (for multiple record types) for a single subject.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsPropagationSetAnalysis : IHasAssessments
{
    /// <summary>Domain being analyzed.</summary>
    public string? Subject { get; private set; }

    /// <summary>Per-record-type DNS propagation summaries.</summary>
    public List<DnsPropagationReportAnalysis> Items { get; } = new();

    /// <summary>Aggregated assessments from all <see cref="Items"/>.</summary>
    public List<Assessment> Assessments { get; } = new();

    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    public void Reset(string? subject = null)
    {
        Subject = subject;
        Items.Clear();
        Assessments.Clear();
    }

    public void Add(DnsPropagationReportAnalysis analysis)
    {
        if (analysis == null) throw new ArgumentNullException(nameof(analysis));
        Subject ??= analysis.Subject;
        Items.Add(analysis);
        if (analysis.Assessments != null && analysis.Assessments.Count > 0)
        {
            Assessments.AddRange(analysis.Assessments);
        }
    }
}

