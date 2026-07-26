using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs targeted DNS health checks that require querying authoritative servers directly
    /// (SOA serial skew and apex A/AAAA consistency across NS).
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsHealthAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Gets or sets the dns configuration value.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional parsed-response override for direct authoritative probes.</summary>
        public Func<IPAddress, DnsMessage, CancellationToken, Task<DnsResponse?>>? QueryResponseOverride { get; set; }

        /// <summary>Gets or sets the name servers value.</summary>
        public List<string> NameServers { get; private set; } = new();
        /// <summary>Gets the soa serial by server value.</summary>
        public Dictionary<string, long> SoaSerialByServer { get; } = new();
        /// <summary>Gets or sets the soa serial consistent value.</summary>
        public bool SoaSerialConsistent { get; private set; }

        /// <summary>Gets the apex addresses by server value.</summary>
        public Dictionary<string, List<string>> ApexAddressesByServer { get; } = new();
        /// <summary>Gets or sets the apex addresses consistent value.</summary>
        public bool ApexAddressesConsistent { get; private set; }

        /// <summary>Gets or sets the servers responsive value.</summary>
        public bool ServersResponsive { get; private set; }

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken) {
            return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Executes the analyze operation.</summary>
        public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSHEALTH", target: domainName);
            Subject = domainName;
            NameServers.Clear();
            SoaSerialByServer.Clear();
            ApexAddressesByServer.Clear();
            SoaSerialConsistent = true;
            ApexAddressesConsistent = true;
            ServersResponsive = true;

            // Discover NS hostnames and their addresses
            var nsAnswers = await QueryDns(domainName, DnsRecordType.NS, cancellationToken).ConfigureAwait(false);
            var nsHosts = nsAnswers.Select(a => a.Data.Trim('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            NameServers.AddRange(nsHosts);
            var nsIps = new List<(string host, IPAddress ip)>();
            foreach (var ns in nsHosts) {
                cancellationToken.ThrowIfCancellationRequested();
                var a = await QueryDns(ns, DnsRecordType.A, cancellationToken).ConfigureAwait(false);
                foreach (var ans in a) {
                    if (IPAddress.TryParse(ans.Data, out var ip)) {
                        nsIps.Add((ns, ip));
                    }
                }
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA, cancellationToken).ConfigureAwait(false);
                foreach (var ans in aaaa) {
                    if (IPAddress.TryParse(ans.Data, out var ip6)) {
                        nsIps.Add((ns, ip6));
                    }
                }
            }

            if (nsIps.Count == 0) {
                return;
            }

            // Query SOA serial and apex A/AAAA directly from each server
            foreach (var (host, ip) in nsIps) {
                cancellationToken.ThrowIfCancellationRequested();
                var serverKey = ip.ToString();
                var serial = await QuerySoaSerial(ip, domainName, cancellationToken);
                if (serial.HasValue) {
                    SoaSerialByServer[serverKey] = serial.Value;
                }
                var apex = await QueryApexAddresses(ip, domainName, cancellationToken);
                if (apex.Count > 0) {
                    ApexAddressesByServer[serverKey] = apex;
                }
            }

            // Evaluate consistency
            if (SoaSerialByServer.Count > 1) {
                var first = SoaSerialByServer.First().Value;
                foreach (var kv in SoaSerialByServer) {
                    if (kv.Value != first) { SoaSerialConsistent = false; break; }
                }
            }

            if (!SoaSerialConsistent) {
                logger?.WriteWarningCode(DnsHealthCodes.SoaSerialSkew, "SOA serial numbers differ across authoritative servers");
            } else {
                logger?.WriteInformationCode(DnsHealthCodes.SoaSerialConsistent, "SOA serial numbers consistent across authoritative servers");
            }

            if (ApexAddressesByServer.Count > 1) {
                string Canonical(List<string> list) {
                    var arr = list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    arr.Sort(StringComparer.OrdinalIgnoreCase);
                    return string.Join(",", arr);
                }
                string? baseline = null;
                foreach (var kv in ApexAddressesByServer) {
                    var canon = Canonical(kv.Value);
                    if (baseline == null) baseline = canon;
                    else if (!string.Equals(baseline, canon, StringComparison.OrdinalIgnoreCase)) { ApexAddressesConsistent = false; break; }
                }
            }

            if (!ApexAddressesConsistent) {
                logger?.WriteWarningCode(DnsHealthCodes.ApexInconsistent, "A/AAAA answers for zone apex differ across authoritative servers");
            }

            ServersResponsive = SoaSerialByServer.Count == nsIps.Count && ApexAddressesByServer.Count == nsIps.Count;
            if (ServersResponsive) {
                logger?.WriteInformationCode(DnsHealthCodes.ServersResponsive, "All authoritative name servers responded to queries");
            }
        }

        private async Task<DnsResponse?> QueryAuthoritativeAsync(IPAddress server, DnsMessage query,
            CancellationToken token) {
            if (QueryResponseOverride != null) {
                return await QueryResponseOverride(server, query, token).ConfigureAwait(false);
            }
            DnsWireQueryResult result = await DnsWireQueryClient.QueryUdpAsync(
                server.ToString(), 53, query, 4000, useTcpFallback: true, cancellationToken: token).ConfigureAwait(false);
            return result.Response;
        }

        private async Task<long?> QuerySoaSerial(IPAddress server, string zone, CancellationToken token) {
            try {
                var query = new DnsMessage(zone, DnsRecordType.SOA, new DnsMessageOptions(RecursionDesired: false));
                DnsResponse? response = await QueryAuthoritativeAsync(server, query, token).ConfigureAwait(false);
                string? data = response?.Answers
                    .Where(answer => answer.Type == DnsRecordType.SOA)
                    .Select(answer => answer.Data ?? answer.DataRaw)
                    .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
                string[] parts = (data ?? string.Empty).Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 3 && long.TryParse(parts[2], out long serial) ? serial : (long?)null;
            } catch (OperationCanceledException) { throw; } catch { }
            return null;
        }

        private async Task<List<string>> QueryApexAddresses(IPAddress server, string zone, CancellationToken token) {
            var list = new List<string>();
            async Task Fetch(DnsRecordType type) {
                var query = new DnsMessage(zone, type, new DnsMessageOptions(RecursionDesired: false));
                DnsResponse? response = await QueryAuthoritativeAsync(server, query, token).ConfigureAwait(false);
                list.AddRange((response?.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == type && !string.IsNullOrWhiteSpace(answer.Data ?? answer.DataRaw))
                    .Select(answer => answer.Data ?? answer.DataRaw));
            }
            try { await Fetch(DnsRecordType.A).ConfigureAwait(false); } catch (OperationCanceledException) { throw; } catch { }
            try { await Fetch(DnsRecordType.AAAA).ConfigureAwait(false); } catch (OperationCanceledException) { throw; } catch { }
            return list;
        }
    }
}
