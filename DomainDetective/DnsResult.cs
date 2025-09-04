using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Represents a DNS query result.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// The <see cref="Data"/> property exposes raw record strings exactly as
    /// returned by the DNS resolver.
    /// </remarks>
    public class DnsResult {
        /// <summary>Gets or sets the queried name.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>Gets or sets the raw data returned.</summary>
        public string[] Data { get; set; } = Array.Empty<string>();
        /// <summary>Gets or sets the data joined into a single string.</summary>
        public string DataJoined { get; set; } = string.Empty;
        /// <summary>Gets or sets the time to live value.</summary>
        public int Ttl { get; set; }

        internal ServiceType ServiceType { get; set; }

        /// <summary>
        ///     Creates a <see cref="DnsResult"/> from a <see cref="DnsAnswer"/>.
        /// </summary>
        public static DnsResult FromDnsAnswer(DnsAnswer answer) {
            return new DnsResult {
                Name = answer.Name,
                Data = answer.DataStringsEscaped,
                DataJoined = answer.Data,
                Ttl = answer.TTL
            };
        }
    }
}