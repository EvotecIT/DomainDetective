using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Collects TTL values for common DNS records and exposes warnings
    /// when values fall outside recommended ranges.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsTtlAnalysis {
        private readonly List<string> _warnings = new();
        public bool DnsSecSigned { get; private set; }

        /// <summary>Gets TTL values for A records.</summary>
        public IReadOnlyList<int> ATtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for AAAA records.</summary>
        public IReadOnlyList<int> AaaaTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for MX records.</summary>
        public IReadOnlyList<int> MxTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for NS records.</summary>
        public IReadOnlyList<int> NsTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets the TTL value for the SOA record.</summary>
        public int SoaTtl { get; private set; }
        /// <summary>Collection of warning messages produced during analysis.</summary>
        public IReadOnlyList<string> Warnings => _warnings;

        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        /// <summary>
        /// Queries DNS records for TTL values and evaluates them.
        /// </summary>
        /// <param name="domainName">Domain name to analyze.</param>
        /// <param name="logger">Optional logger used for diagnostics.</param>
        public async Task Analyze(string domainName, InternalLogger logger) {
            _warnings.Clear();
            ATtls = Array.Empty<int>();
            AaaaTtls = Array.Empty<int>();
            MxTtls = Array.Empty<int>();
            NsTtls = Array.Empty<int>();
            SoaTtl = 0;

            var aRecords = await QueryDns(domainName, DnsRecordType.A);
            var aaaaRecords = await QueryDns(domainName, DnsRecordType.AAAA);
            var mxRecords = await QueryDns(domainName, DnsRecordType.MX);
            var nsRecords = await QueryDns(domainName, DnsRecordType.NS);
            var soaRecords = await QueryDns(domainName, DnsRecordType.SOA);
            var dsRecords = await QueryDns(domainName, DnsRecordType.DS);

            DnsSecSigned = dsRecords.Length > 0;

            ATtls = aRecords.Select(r => r.TTL).ToArray();
            AaaaTtls = aaaaRecords.Select(r => r.TTL).ToArray();
            MxTtls = mxRecords.Select(r => r.TTL).ToArray();
            NsTtls = nsRecords.Select(r => r.TTL).ToArray();
            SoaTtl = soaRecords.Length > 0 ? soaRecords[0].TTL : 0;

            Evaluate("A", ATtls, 300, 86400, DnsSecSigned);
            Evaluate("AAAA", AaaaTtls, 300, 86400, DnsSecSigned);
            Evaluate("MX", MxTtls, 300, 86400, DnsSecSigned);
            Evaluate("NS", NsTtls, 300, 86400, DnsSecSigned);
            if (SoaTtl > 0) {
                Evaluate("SOA", new[] { SoaTtl }, 300, 86400, DnsSecSigned);
            }
        }

        private void Evaluate(string recordType, IEnumerable<int> ttls, int min, int max, bool dnssecSigned) {
            foreach (var ttl in ttls) {
                if (dnssecSigned && ttl >= min && ttl < 3600) {
                    _warnings.Add($"{recordType} TTL {ttl} is shorter than recommended 3600 seconds for DNSSEC-signed zones.");
                }
                if (ttl < min) {
                    _warnings.Add($"{recordType} TTL {ttl} is shorter than recommended {min} seconds.");
                } else if (ttl > max) {
                    _warnings.Add($"{recordType} TTL {ttl} exceeds recommended {max} seconds.");
                }
            }
        }
    }
}
