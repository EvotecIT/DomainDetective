namespace DomainDetective.Definitions;

/// <summary>Confidence level for the classification decision.</summary>
public enum MailDomainClassificationConfidence {
    /// <summary>Multiple strong indicators align; no conflicting signals.</summary>
    High,
    /// <summary>Clear indicators present but some ambiguity exists.</summary>
    Medium,
    /// <summary>Limited or conflicting evidence.</summary>
    Low
}

