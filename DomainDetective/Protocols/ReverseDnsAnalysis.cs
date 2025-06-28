using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Validates PTR records for MX hosts.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class ReverseDnsAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Represents PTR lookup result for a single address.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class ReverseDnsResult {
            public string IpAddress { get; set; }
            public string? PtrRecord { get; set; }
            public string ExpectedHost { get; set; }
            /// <summary>True when <see cref="PtrRecord"/> equals <see cref="ExpectedHost"/>.</summary>
            public bool IsValid => string.Equals(PtrRecord?.TrimEnd('.'), ExpectedHost.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Gets the collection of PTR results.</summary>
        public List<ReverseDnsResult> Results { get; private set; } = new();
        /// <summary>Indicates whether all MX hosts have matching PTR records.</summary>
        public bool AllValid => Results.All(r => r.IsValid);

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        /// <summary>
        /// Checks PTR records for the specified MX hosts.
        /// </summary>
        /// <param name="hosts">MX host names.</param>
        /// <param name="logger">Optional diagnostic logger.</param>
        public async Task AnalyzeHosts(IEnumerable<string> hosts, InternalLogger? logger = null) {
            Results = new List<ReverseDnsResult>();
            foreach (var host in hosts) {
                if (string.IsNullOrWhiteSpace(host)) {
                    continue;
                }
                var aRecords = await QueryDns(host, DnsRecordType.A);
                var aaaaRecords = await QueryDns(host, DnsRecordType.AAAA);
                foreach (var record in aRecords.Concat(aaaaRecords ?? Array.Empty<DnsAnswer>())) {
                    if (!IPAddress.TryParse(record.Data, out var ip)) {
                        continue;
                    }
                    var ptrName = ip.ToPtrFormat() + (ip.AddressFamily == AddressFamily.InterNetworkV6 ? ".ip6.arpa" : ".in-addr.arpa");
                    var ptrAnswers = await QueryDns(ptrName, DnsRecordType.PTR);
                    string? ptr = null;
                    if (ptrAnswers.Length > 0) {
                        ptr = ptrAnswers[0].Data.TrimEnd('.');
                    }
                    Results.Add(new ReverseDnsResult {
                        IpAddress = ip.ToString(),
                        PtrRecord = ptr,
                        ExpectedHost = host.TrimEnd('.')
                    });
                    logger?.WriteVerbose($"PTR for {ip} -> {ptr}");
                }
            }
        }

        /// <example>
        ///   <summary>Validate PTR records for MX hosts</summary>
        ///   <code>
        ///   var hc = new DomainHealthCheck();
        ///   await hc.Verify("example.com", new[] { HealthCheckType.REVERSEDNS });
        ///   </code>
        /// </example>
    }
}
