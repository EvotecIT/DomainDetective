namespace DomainDetective;

/// <summary>
/// Identifies the origin of the IP address used for an IP-based DNSBL query.
/// </summary>
public enum DnsblIpSource
{
    /// <summary>IP address was provided directly by the user.</summary>
    UserProvided = 0,
    /// <summary>Domain-level listing (URIBL/DBL); no IP resolution involved.</summary>
    Domain = 5,
    /// <summary>IP address was obtained from a domain's apex A record.</summary>
    ApexA = 1,
    /// <summary>IP address was obtained from a domain's apex AAAA record.</summary>
    ApexAAAA = 2,
    /// <summary>IP address was obtained from an MX host's A record.</summary>
    MxA = 3,
    /// <summary>IP address was obtained from an MX host's AAAA record.</summary>
    MxAAAA = 4,
}
