namespace DomainDetective {
    /// <summary>
    /// Represents a public DNS server used for propagation checks.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class PublicDnsEntry {
        /// <summary>Gets the country of the DNS server.</summary>
        public string Country { get; init; }
        /// <summary>Gets the IP address of the DNS server.</summary>
        public string IPAddress { get; init; }
        /// <summary>Gets the host name of the DNS server.</summary>
        public string HostName { get; init; }
        /// <summary>Gets the location description.</summary>
        public string Location { get; init; }
        /// <summary>Gets the ASN of the DNS server.</summary>
        public string ASN { get; init; }
        /// <summary>Gets the ASN name of the DNS server.</summary>
        public string ASNName { get; init; }
        /// <summary>Gets a value indicating whether the server is enabled.</summary>
        public bool Enabled { get; init; } = true;
    }
}
