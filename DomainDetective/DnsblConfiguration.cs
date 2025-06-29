namespace DomainDetective {
using System.Collections.Generic;

    /// <summary>
    /// Configuration for DNS block list providers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsblConfiguration {
        /// <summary>Gets or sets the list of DNSBL providers.</summary>
        public List<DnsblEntry> Providers { get; set; } = new();

        /// <summary>Gets or sets domain based block lists.</summary>
        public List<DnsblEntry> DomainBlockLists { get; set; } = new();
    }
}
