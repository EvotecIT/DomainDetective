using System;

namespace DomainDetective;

/// <summary>
/// Describes certificate transparency operations that a provider can execute.
/// </summary>
[Flags]
public enum CtIngestionOperation
{
    /// <summary>No certificate transparency operation is requested.</summary>
    None = 0,

    /// <summary>Discover host names below a registered or monitored domain.</summary>
    DiscoverSubdomains = 1,

    /// <summary>Retrieve the latest known certificate for an exact host name.</summary>
    GetLatestCertificate = 2,

    /// <summary>Retrieve historical certificates for an exact host name.</summary>
    GetCertificateHistory = 4,

    /// <summary>Retrieve certificates for a domain and its discovered host names.</summary>
    GetDomainTreeCertificates = 8
}
