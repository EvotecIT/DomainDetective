namespace DomainDetective.Providers.Email;

/// <summary>Defines values for dmarc subdomain policy recommendation.</summary>
public enum DmarcSubdomainPolicyRecommendation
{
    /// <summary>Represents the none value.</summary>
    None = 0,
    /// <summary>Represents the match parent value.</summary>
    MatchParent = 1,
    /// <summary>Represents the quarantine value.</summary>
    Quarantine = 2,
    /// <summary>Represents the reject value.</summary>
    Reject = 3
}

