namespace DomainDetective;

/// <summary>
/// Describes the recognized CAA tag types.
/// </summary>
public enum CAATagType
{
    /// <summary>An unrecognized tag.</summary>
    Unknown,
    /// <summary>Authorizes issuance for a specific CA.</summary>
    Issue,
    /// <summary>Authorizes wildcard certificate issuance.</summary>
    IssueWildcard,
    /// <summary>Provides incident report contact information.</summary>
    Iodef,
    /// <summary>Authorizes issuance for S/MIME certificates.</summary>
    IssueMail
}
