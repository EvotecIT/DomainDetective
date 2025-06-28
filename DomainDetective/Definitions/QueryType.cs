namespace DomainDetective;

/// <summary>
/// Defines the supported DNS query mechanisms.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum QueryType {
    /// <summary>Standard UDP/TCP DNS query.</summary>
    Standard,
    /// <summary>Query using DNS over HTTPS.</summary>
    DnsOverHttps,
}