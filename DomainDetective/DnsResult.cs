using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective {
    /// <summary>
    /// Represents a DNS query result.
    /// </summary>
    public class DnsResult {
        /// <summary>Gets or sets the queried name.</summary>
        public string Name { get; set; }
        /// <summary>Gets or sets the raw data returned.</summary>
        public string[] Data { get; set; }
        /// <summary>Gets or sets the data joined into a single string.</summary>
        public string DataJoined { get; set; }
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