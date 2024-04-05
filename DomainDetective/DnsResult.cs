using System;
using System.Collections.Generic;
using System.Linq;
using DnsClientX;

namespace DomainDetective {
    public class DnsResult {
        public string Name { get; set; }
        public string[] Data { get; set; }
        public string DataJoined { get; set; }

        internal ServiceType ServiceType { get; set; }
    }
}
