using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Validates PTR records for MX hosts.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class ReverseDnsAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        /// <summary>Provides DNS configuration for lookups.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Optional override returning raw DNS responses.</summary>
        public Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }

        private const int MaxLabelLength = 63;
        private const int MaxHostNameLength = 253;
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
        private static readonly Regex _labelRegex = new(
            $"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,{MaxLabelLength - 2}}}[a-zA-Z0-9])?$",
            RegexOptions.Compiled,
            RegexTimeout);

        private static readonly string[] CloudHints = new[] {
            "amazonaws.com", "compute-1.amazonaws.com", "googleusercontent.com", "cloudflare.com", "azure.com", "windows.net",
            "digitalocean.com", "linode.com", "ovh.net", "hetzner", "akamaiedge.net", "akamaitechnologies.com", "fastly.net"
        };

        private const int ParallelLookupLimit = 4;

        private static string NormalizeHost(string? host) =>
            host?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;

        private static bool IsValidPtrName(string name) {
            if (string.IsNullOrWhiteSpace(name) || name.Length > MaxHostNameLength) {
                return false;
            }

            var labels = NormalizeHost(name).Split('.');
            foreach (var label in labels) {
                if (label.Length > MaxLabelLength || !_labelRegex.IsMatch(label)) {
                    return false;
                }
            }

            return true;
        }

        /// <summary>Represents PTR lookup result for a single address.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class ReverseDnsResult {
            public string IpAddress { get; set; } = string.Empty;
            public string? PtrRecord { get; set; }
            /// <summary>All PTR records returned for the IP.</summary>
            public List<string> PtrRecords { get; } = new();
            public string ExpectedHost { get; set; } = string.Empty;
            /// <summary>True when <see cref="PtrRecord"/> equals <see cref="ExpectedHost"/>.</summary>
            public bool IsValid => string.Equals(PtrRecord, ExpectedHost, StringComparison.Ordinal);
            /// <summary>True when any PTR hostname resolves back to <see cref="IpAddress"/>.</summary>
            public bool FcrDnsValid { get; set; }
        }

        /// <summary>Gets the collection of PTR results.</summary>
        public List<ReverseDnsResult> Results { get; private set; } = new();
        /// <summary>Indicates whether all MX hosts have matching PTR records.</summary>
        public bool AllValid => Results?.All(r => r.IsValid) == true;

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
            var bag = new ConcurrentBag<ReverseDnsResult>();
            var hostList = hosts?.Where(h => !string.IsNullOrWhiteSpace(h)).ToList() ?? new List<string>();
            using var semaphore = new SemaphoreSlim(ParallelLookupLimit);
            var tasks = hostList.Select(async host => {
                await semaphore.WaitAsync();
                try {
                    var hostResults = await AnalyzeHost(host, logger);
                    foreach (var r in hostResults) {
                        bag.Add(r);
                    }
                } finally {
                    semaphore.Release();
                }
            });
            await Task.WhenAll(tasks);
            Results = bag.ToList();
        }

        private async Task<List<ReverseDnsResult>> AnalyzeHost(string host, InternalLogger? logger) {
            var results = new List<ReverseDnsResult>();
            if (string.IsNullOrWhiteSpace(host)) {
                return results;
            }

            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RDNS", target: host) : null;
            var aTask = QueryDns(host, DnsRecordType.A);
            var aaaaTask = QueryDns(host, DnsRecordType.AAAA);
            await Task.WhenAll(aTask, aaaaTask);
            var aRecords = aTask.Result;
            var aaaaRecords = aaaaTask.Result ?? Array.Empty<DnsAnswer>();
            foreach (var record in aRecords.Concat(aaaaRecords)) {
                var recData = record.Data ?? record.DataRaw;
                if (!IPAddress.TryParse(recData, out var ip)) {
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
                            logger?.WriteWarningCode(ReverseDnsCodes.TruncatedNoRecords, $"PTR query for {ip} was truncated and returned no records after TCP retry");
                        }
                    }
                } else {
                    ptrAnswers = await QueryDns(ptrName, DnsRecordType.PTR);
                }

                var ptrs = new List<string>();
                foreach (var ans in ptrAnswers) {
                    var rawPtr = ans.Data ?? ans.DataRaw;
                    if (IsValidPtrName(rawPtr)) {
                        var norm = NormalizeHost(rawPtr);
                        if (!string.IsNullOrEmpty(norm)) {
                            ptrs.Add(norm);
                        }
                    } else {
                        logger?.WriteWarningCode(ReverseDnsCodes.MalformedPtr, $"Malformed PTR record: {rawPtr}");
                    }
                }

                string? ptr = ptrs.FirstOrDefault();
                var result = new ReverseDnsResult {
                    IpAddress = ip.ToString(),
                    PtrRecord = ptr,
                    ExpectedHost = NormalizeHost(host)
                };
                result.PtrRecords.AddRange(ptrs);

                if (ptrs.Count > 0) {
                    logger?.WriteInformationCode(ReverseDnsCodes.PtrRecordPresent, "PTR record present for {0}", ip);
                    foreach (var p in ptrs) {
                        var fwdATask = QueryDns(p, DnsRecordType.A);
                        var fwdAaaaTask = QueryDns(p, DnsRecordType.AAAA);
                        await Task.WhenAll(fwdATask, fwdAaaaTask);
                        if (fwdATask.Result.Concat(fwdAaaaTask.Result).Any(r => string.Equals(r.Data ?? r.DataRaw, ip.ToString(), StringComparison.Ordinal))) {
                            result.FcrDnsValid = true;
                            break;
                        }
                    }
                    if (result.IsValid) {
                        logger?.WriteInformationCode(ReverseDnsCodes.PtrMatchesMx, "PTR {0} matches MX host {1}", ptr, host);
                    }
                    if (result.FcrDnsValid) {
                        logger?.WriteInformationCode(ReverseDnsCodes.ForwardConfirmed, "PTR {0} resolves back to {1}", string.Join(", ", ptrs), ip);
                    } else {
                        logger?.WriteWarningCode(ReverseDnsCodes.ForwardMismatch, "PTR {0} does not map back to {1}", string.Join(", ", ptrs), ip);
                    }

                    if (ptrs.Any(p => CloudHints.Any(h => p.IndexOf(h, StringComparison.Ordinal) >= 0))) {
                        logger?.WriteInformationCode(ReverseDnsCodes.SharedCloudManyToOne, "PTR points to shared cloud host: {0}", string.Join(", ", ptrs));
                    }
                }

                results.Add(result);
                logger?.WriteVerbose($"PTR for {ip} -> {string.Join(", ", ptrs)}");
            }

            return results;
        }

        /// <example>
        ///   <summary>Validate PTR records for MX hosts</summary>
        ///   <code>
        ///   var hc = new DomainHealthCheck();
        ///   await hc.Verify("example.com", new[] { HealthCheckType.REVERSEDNS });
        ///   </code>
        /// </example>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
    }
}
