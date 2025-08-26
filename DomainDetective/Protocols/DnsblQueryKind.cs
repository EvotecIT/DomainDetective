namespace DomainDetective;

/// <summary>
/// Distinguishes what was queried against DNSBL providers.
/// </summary>
public enum DnsblQueryKind {
    /// <summary>Query was made for a domain name (URIBL/DBL style).</summary>
    Domain = 0,
    /// <summary>Query was made for an IP address (address-based DNSBL).</summary>
    IpAddress = 1
}

