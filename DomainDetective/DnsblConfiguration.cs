namespace DomainDetective;

using System.Collections.Generic;

public class DnsblConfiguration {
    public List<DnsblEntry> Providers { get; set; } = new();
}
