using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Validates PTR records for MX hosts.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class ReverseDnsAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        public Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }

        private static readonly Regex _labelRegex = new(
            "^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
            RegexOptions.Compiled);

        private static bool IsValidPtrName(string name) {
            if (string.IsNullOrWhiteSpace(name) || !name.EndsWith(".", StringComparison.Ordinal)) {
                return false;
            }

            var labels = name.TrimEnd('.').Split('.');
            foreach (var label in labels) {
                if (!_labelRegex.IsMatch(label)) {
                    return false;
                }
            }

            return true;
        }

        /// <summary>Represents PTR lookup result for a single address.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class ReverseDnsResult {
            public string IpAddress { get; set; }
            public string? PtrRecord { get; set; }
            /// <summary>All PTR records returned for the IP.</summary>
            public List<string> PtrRecords { get; } = new();
            public string ExpectedHost { get; set; }
            /// <summary>True when <see cref="PtrRecord"/> equals <see cref="ExpectedHost"/>.</summary>
            public bool IsValid => string.Equals(
                PtrRecord?.TrimEnd('.'),
                ExpectedHost?.TrimEnd('.'),
                StringComparison.OrdinalIgnoreCase);
            /// <summary>True when any PTR hostname resolves back to <see cref="IpAddress"/>.</summary>
            public bool FcrDnsValid { get; set; }
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

        private async Task<IEnumerable<DnsResponse>> QueryDnsFull(string name, DnsRecordType type) {
            if (QueryDnsFullOverride != null) {
                return await QueryDnsFullOverride(name, type);
            }

            return await DnsConfiguration.QueryFullDNS(new[] { name }, type);
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
                    DnsAnswer[] ptrAnswers;
                    bool truncated = false;
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6) {
                        var resp = await QueryDnsFull(ptrName, DnsRecordType.PTR);
                        truncated = resp.Any(r => r.IsTruncated);
                        ptrAnswers = resp.SelectMany(r => r.Answers).ToArray();
                        if (truncated) {
                            if (QueryDnsOverride != null) {
                                ptrAnswers = await QueryDnsOverride(ptrName, DnsRecordType.PTR);
                            } else {
                                var tcpConfig = new DnsConfiguration(DnsEndpoint.SystemTcp, DnsConfiguration.DnsSelectionStrategy);
                                ptrAnswers = await tcpConfig.QueryDNS(ptrName, DnsRecordType.PTR);
                            }
                            if (ptrAnswers.Length == 0) {
                                logger?.WriteWarning($"PTR query for {ip} was truncated and returned no records after TCP retry");
                            }
                        }
                    } else {
                        ptrAnswers = await QueryDns(ptrName, DnsRecordType.PTR);
                    }

                    var ptrs = new List<string>();
                    foreach (var ans in ptrAnswers) {
                        var rawPtr = ans.Data;
                        if (IsValidPtrName(rawPtr)) {
                            ptrs.Add(rawPtr.TrimEnd('.'));
                        } else {
                            logger?.WriteWarning($"Malformed PTR record: {rawPtr}");
                        }
                    }

                    string? ptr = ptrs.FirstOrDefault();
                    var result = new ReverseDnsResult {
                        IpAddress = ip.ToString(),
                        PtrRecord = ptr,
                        ExpectedHost = host.TrimEnd('.')
                    };
                    result.PtrRecords.AddRange(ptrs);

                    if (ptrs.Count > 0) {
                        foreach (var p in ptrs) {
                            var fwdA = await QueryDns(p, DnsRecordType.A);
                            var fwdAaaa = await QueryDns(p, DnsRecordType.AAAA);
                            if (fwdA.Concat(fwdAaaa).Any(r => string.Equals(r.Data, ip.ToString(), StringComparison.Ordinal))) {
                                result.FcrDnsValid = true;
                                break;
                            }
                        }
                    }

                    Results.Add(result);
                    logger?.WriteVerbose($"PTR for {ip} -> {string.Join(", ", ptrs)}");
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
