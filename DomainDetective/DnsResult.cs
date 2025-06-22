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

        internal ServiceType ServiceType { get; set; }
    }
}