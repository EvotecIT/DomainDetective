namespace DomainDetective;

using System.Collections.Generic;

/// <summary>
/// Configuration for DNS block list providers.
/// </summary>
public class DnsblConfiguration {
    /// <summary>
    /// Gets or sets the list of DNSBL providers.
    /// </summary>
    public List<DnsblEntry> Providers { get; set; } = new();
}
