using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Represents the outcome of a single DNSBL query entry.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DNSBLRecord {
        /// <summary>Plain IPv4/IPv6 for IP-based checks; null for domain-based checks.</summary>
        public string? IpAddress { get; set; }

        /// <summary>Indicates where the IP address originated from (for IP-based checks).</summary>
        public DnsblIpSource? IpSource { get; set; }

        /// <summary>Optional host label that produced the IP (e.g., apex domain or MX host).</summary>
        public string? SourceHost { get; set; }

        /// <summary>Indicates whether this record came from a domain or IP-based query.</summary>
        public DnsblQueryKind QueryKind { get; set; }

        /// <summary>Gets or sets the blacklist domain.</summary>
        public string BlackList { get; set; } = null!;

        /// <summary>Gets or sets a value indicating whether the address was listed.</summary>
        public bool IsBlackListed { get; set; }

        /// <summary>Gets or sets the raw DNSBL response.</summary>
        public string Answer { get; set; } = null!;

        /// <summary>Gets or sets the interpreted meaning of <see cref="Answer"/>.</summary>
        public string ReplyMeaning { get; set; } = null!;

        /// <summary>Gets or sets the fully qualified domain name that was queried.</summary>
        public string FQDN { get; set; } = null!;

        /// <summary>
        /// DNSBL base query label (e.g., reversed IP or domain without provider).
        /// For provider-specific full query, see <see cref="FQDN"/>.
        /// </summary>
        public string Query { get; set; } = null!;
    }

    /// <summary>
    /// Aggregates multiple DNSBL query outcomes for a host.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DNSQueryResult {
        /// <summary>Gets or sets the host that was checked.</summary>
        public string Host { get; set; } = null!;

        /// <summary>Gets or sets the DNSBL results.</summary>
        public IEnumerable<DNSBLRecord> DNSBLRecords { get; set; } = Array.Empty<DNSBLRecord>();

        /// <summary>Gets the number of blacklists that reported a listing.</summary>
        public int Listed => DNSBLRecords.Count(record => record.IsBlackListed);

        /// <summary>Gets the names of blacklists that reported a listing.</summary>
        public List<string> ListedBlacklist =>
            DNSBLRecords.Where(record => record.IsBlackListed).Select(record => record.BlackList).ToList();

        /// <summary>Gets the number of lists where the host was not found.</summary>
        public int NotListed => DNSBLRecords.Count(record => !record.IsBlackListed);

        /// <summary>Gets the total number of DNSBL checks performed.</summary>
        public int Total => DNSBLRecords.Count();

        /// <summary>Gets a value indicating whether the host was listed on any blacklist.</summary>
        public bool IsBlacklisted => Listed > 0;
    }

    /// <summary>
    /// Represents a DNSBL server configuration entry.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsblEntry {
        /// <summary>Gets or sets the blacklist domain.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>Gets or sets a value indicating whether the entry is used during checks.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Gets or sets optional descriptive text.</summary>
        public string? Comment { get; set; }

        /// <summary>Gets or sets provider specific reply codes.</summary>
        public Dictionary<string, DnsblReplyCode> ReplyCodes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Gets or sets the DNS port to use for queries.</summary>
        public int Port { get; set; } = 53;

        public DnsblEntry() { }

        public DnsblEntry(string domain, bool enabled = true, string? comment = null, int port = 53) {
            Domain = domain;
            Enabled = enabled;
            Comment = comment;
            Port = port;
        }
    }
}
