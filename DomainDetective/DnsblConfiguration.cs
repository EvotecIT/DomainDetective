namespace DomainDetective {
using System.Collections.Generic;

    /// <summary>
    /// Configuration for DNS block list providers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// The configuration is typically loaded from JSON and defines which lists
    /// are consulted when performing blacklist checks.
    /// </remarks>
    public class DnsblConfiguration {
        /// <summary>Gets or sets the list of DNSBL providers.</summary>
        public DnsblEntryCollection Providers { get; set; } = new();

        /// <summary>Gets or sets domain based block lists.</summary>
        public DnsblEntryCollection DomainBlockLists { get; set; } = new();

        /// <summary>Gets or sets IP based block lists.</summary>
        public BlockListEntryCollection IpBlockLists { get; set; } = new();
    }
}
