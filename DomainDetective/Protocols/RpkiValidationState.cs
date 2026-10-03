namespace DomainDetective;

/// <summary>Describes a prefix and origin ASN's RPKI validation outcome.</summary>
public enum RpkiValidationState {
    /// <summary>No detailed outcome was supplied by the provider.</summary>
    Unspecified,
    /// <summary>A covering ROA authorizes this origin and prefix length.</summary>
    Valid,
    /// <summary>A covering ROA does not authorize the origin ASN.</summary>
    InvalidOriginAsn,
    /// <summary>The prefix length exceeds the covering ROA's maximum length.</summary>
    InvalidPrefixLength,
    /// <summary>The provider reports an invalid route without a more specific reason.</summary>
    Invalid,
    /// <summary>No covering ROA was found.</summary>
    NotFound,
    /// <summary>The lookup failed or returned an unsupported response.</summary>
    QueryFailed
}
