namespace DomainDetective;

/// <summary>
/// Defines the supported DNS query mechanisms.
/// </summary>
public enum QueryType {
    /// <summary>Standard UDP/TCP DNS query.</summary>
    Standard,
    /// <summary>Query using DNS over HTTPS.</summary>
    DnsOverHttps,
}