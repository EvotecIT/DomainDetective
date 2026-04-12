using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Variant generation algorithm used for a typosquatting candidate.
/// </summary>
public enum TyposquattingVariantKind
{
    /// <summary>Defines values for typosquatting risk level.</summary>
    Omission,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Repetition,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Homoglyph,
    /// <summary>Defines values for typosquatting risk level.</summary>
    BrandCombination,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Addition,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Bitsquatting,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Cyrillic,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Hyphenation,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Insertion,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Plural,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Replacement,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Subdomain,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Transposition,
    /// <summary>Defines values for typosquatting risk level.</summary>
    VowelSwap,
    /// <summary>Defines values for typosquatting risk level.</summary>
    Dictionary,
    /// <summary>Defines values for typosquatting risk level.</summary>
    TldSwap
}

/// <summary>
/// Severity band derived from the candidate risk score.
/// </summary>
public enum TyposquattingRiskLevel
{
    /// <summary>Defines values for typosquatting disposition.</summary>
    None,
    /// <summary>Defines values for typosquatting disposition.</summary>
    Low,
    /// <summary>Defines values for typosquatting disposition.</summary>
    Medium,
    /// <summary>Defines values for typosquatting disposition.</summary>
    High,
    /// <summary>Defines values for typosquatting disposition.</summary>
    Critical
}

/// <summary>
/// Analyst-friendly disposition derived from combined typosquatting signals.
/// </summary>
public enum TyposquattingDisposition
{
    /// <summary>Provides typosquatting candidate functionality.</summary>
    Unknown,
    /// <summary>Provides typosquatting candidate functionality.</summary>
    Available,
    /// <summary>Provides typosquatting candidate functionality.</summary>
    DefensiveOwned,
    /// <summary>Provides typosquatting candidate functionality.</summary>
    Monitor,
    /// <summary>Provides typosquatting candidate functionality.</summary>
    LikelyImpersonation,
    /// <summary>Provides typosquatting candidate functionality.</summary>
    LikelyMalicious
}

/// <summary>
/// Structured result for a single typosquatting candidate.
/// </summary>
public sealed class TyposquattingCandidate
{
    /// <summary>Candidate domain name.</summary>
    public string Domain { get; init; } = string.Empty;

    /// <summary>Variant generation algorithm used to produce the candidate.</summary>
    public TyposquattingVariantKind Kind { get; init; }

    /// <summary>Levenshtein distance between the analyzed domain and the candidate.</summary>
    public int EditDistance { get; init; }

    /// <summary>IPv4 answers observed for the candidate.</summary>
    public IReadOnlyList<string> ARecords { get; internal set; } = Array.Empty<string>();

    /// <summary>IPv6 answers observed for the candidate.</summary>
    public IReadOnlyList<string> AaaaRecords { get; internal set; } = Array.Empty<string>();

    /// <summary>Name server answers observed for the candidate.</summary>
    public IReadOnlyList<string> NsRecords { get; internal set; } = Array.Empty<string>();

    /// <summary>Mail exchanger answers observed for the candidate.</summary>
    public IReadOnlyList<string> MxRecords { get; internal set; } = Array.Empty<string>();

    /// <summary>Optional richer enrichment collected for this candidate.</summary>
    public TyposquattingCandidateEnrichment? Enrichment { get; internal set; }

    /// <summary>Calculated risk score for analyst prioritization.</summary>
    public int RiskScore { get; internal set; }

    /// <summary>Severity band derived from <see cref="RiskScore"/>.</summary>
    public TyposquattingRiskLevel RiskLevel { get; internal set; }

    /// <summary>Short human-readable risk explanation.</summary>
    public string RiskSummary { get; internal set; } = string.Empty;

    /// <summary>Signals that contributed to <see cref="RiskScore"/>.</summary>
    public IReadOnlyList<string> RiskReasons { get; internal set; } = Array.Empty<string>();

    /// <summary>Analyst-friendly combined verdict for triage.</summary>
    public TyposquattingDisposition Disposition { get; internal set; }

    /// <summary>Short human-readable disposition explanation.</summary>
    public string DispositionSummary { get; internal set; } = string.Empty;

    /// <summary>Signals that contributed to <see cref="Disposition"/>.</summary>
    public IReadOnlyList<string> DispositionReasons { get; internal set; } = Array.Empty<string>();

    /// <summary>Infrastructure cluster assigned from shared external registrar, NS, or ASN signals.</summary>
    public TyposquattingInfrastructureCluster? InfrastructureCluster { get; internal set; }

    /// <summary>Ownership comparison result against the source domain.</summary>
    public TyposquattingOwnershipMatch? Ownership { get; internal set; }

    /// <summary>Content similarity comparison result against the source domain.</summary>
    public TyposquattingContentSimilarityMatch? ContentSimilarity { get; internal set; }

    /// <summary>Visual similarity comparison result against the source domain.</summary>
    public TyposquattingVisualSimilarityMatch? VisualSimilarity { get; internal set; }

    /// <summary>True when the candidate resolves to an A or AAAA address.</summary>
    public bool Resolves => ARecords.Count > 0 || AaaaRecords.Count > 0;

    /// <summary>True when the candidate shows any DNS footprint that suggests registration.</summary>
    public bool AppearsRegistered => Resolves || NsRecords.Count > 0 || MxRecords.Count > 0;
}
