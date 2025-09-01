namespace DomainDetective;

/// <summary>
/// Distinguishes what was queried against DNSBL providers.
/// </summary>
public enum DnsblQueryKind {
    /// <summary>Query was made for a domain name (URIBL/DBL style).</summary>
    Domain = 0,
    /// <summary>Query was made for an IP address (generic; kept for compatibility).</summary>
    IpAddress = 1,
    /// <summary>Query was made for an IPv4 address (address-based DNSBL).</summary>
    IpAddressV4 = 2,
    /// <summary>Query was made for an IPv6 address (address-based DNSBL).</summary>
    IpAddressV6 = 3
}
