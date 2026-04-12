namespace DomainDetective;

/// <summary>
/// Describes the service-level intent of a certificate transparency query.
/// </summary>
public enum CtCertificateQueryKind
{
    /// <summary>No explicit CT query intent was supplied.</summary>
    Unspecified = 0,

    /// <summary>Retrieve the latest known certificate for one exact host name.</summary>
    ExactHostLatest = 1,

    /// <summary>Retrieve historical certificates for one exact host name.</summary>
    ExactHostHistory = 2,

    /// <summary>Expand a registered or monitored domain into observed subdomains.</summary>
    DomainExpansion = 3,

    /// <summary>Retrieve certificates for a domain tree and its discovered host names.</summary>
    DomainTreeCertificates = 4
}
