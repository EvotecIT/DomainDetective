using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DomainDetective.Providers.Email;

namespace DomainDetective {
    /// <summary>
    ///
    ///
    /// Here are some of the key points for MX record analysis:
    /// 1.	The MX record should exist for the domain.
    /// 2.	The MX record should not point to a CNAME.
    /// 3.	The MX record should not point to an IP address.
    /// 4.	The MX record should not point to a domain that doesn't exist.
    /// 5.	The MX record should not point to a domain that doesn't have an A or AAAA record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class MXAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>DNS configuration used for lookups.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>
        /// Optional override for the authoritative answers the TTL comparisons use. Return null when no authoritative
        /// server answered. Without it, TTLs come from the zone's own name servers (or from
        /// <see cref="QueryDnsOverride"/> answers, which carry fixed TTLs).
        /// </summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]?>>? AuthoritativeQueryOverride { private get; set; }

        /// <summary>MX records discovered during analysis.</summary>
        public List<string> MxRecords { get; private set; } = new List<string>();

        /// <summary>
        /// TTL values (seconds) for each MX record answer: the configured TTLs from the domain's authoritative name
        /// servers when <see cref="TtlsFromAuthoritativeServers"/> is true, otherwise the resolver's answer.
        /// </summary>
        /// <remarks>
        /// A caching resolver reports the time an answer has left in its cache, which counts down between runs, so
        /// TTL comparisons and TTL findings use authoritative answers only.
        /// </remarks>
        public IReadOnlyList<int> MxRecordTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Minimum TTL (seconds) across MX answers (ignores 0).</summary>
        public int? MinMxTtl { get; private set; }
        /// <summary>Maximum TTL (seconds) across MX answers (ignores 0).</summary>
        public int? MaxMxTtl { get; private set; }
        /// <summary>Average TTL (seconds) across MX answers (ignores 0).</summary>
        public double? AvgMxTtl { get; private set; }

        /// <summary>Indicates whether at least one MX record exists.</summary>
        public bool MxRecordExists { get; private set; } // should be true
        /// <summary>Indicates that a record incorrectly points to a CNAME.</summary>
        public bool PointsToCname { get; private set; } // should be false

        /// <summary>Indicates that a record incorrectly points to an IP address.</summary>
        public bool PointsToIpAddress { get; private set; } // should be false

        /// <summary>Indicates that a record points to a non-existent domain.</summary>
        public bool PointsToNonExistentDomain { get; private set; } // should be false

        /// <summary>Indicates that a record points to a domain without A/AAAA records.</summary>
        public bool PointsToDomainWithoutAOrAaaaRecord { get; private set; } // should be false

        /// <summary>Indicates whether MX priorities appear in ascending order.</summary>
        public bool PrioritiesInOrder { get; private set; } // RFC 5321 section 5.1

        /// <summary>Indicates whether backup MX servers are present.</summary>
        public bool HasBackupServers { get; private set; }

        /// <summary>True when an RFC 7505 "Null MX" is present (0 .).</summary>
        public bool HasNullMx { get; private set; }

        /// <summary>True when an MX host points to localhost.</summary>
        public bool PointsToLocalhost { get; private set; }

        /// <summary>True when at least one MX host has an AAAA record.</summary>
        public bool Ipv6Supported { get; private set; }

        /// <summary>
        /// True when the MX TTLs come from the domain's authoritative name servers. When false, no authoritative
        /// server answered: TTL values are the resolver's and the TTL uniformity findings are not raised.
        /// </summary>
        public bool TtlsFromAuthoritativeServers { get; private set; }

        // Integrity checks
        /// <summary>Gets or sets the mx ttl uniform value.</summary>
        public bool MxTtlUniform { get; private set; } = true;
        /// <summary>Gets or sets the mx rrset consistent across ns value.</summary>
        public bool MxRrsetConsistentAcrossNs { get; private set; } = true;
        /// <summary>Gets or sets the target address consistent across ns value.</summary>
        public bool TargetAddressConsistentAcrossNs { get; private set; } = true;

        /// <summary>Relevant standards for MX analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" },
            new StandardReference { Title = "Null MX for No Service", Reference = "RFC 7505", Url = "https://datatracker.ietf.org/doc/html/rfc7505" }
        };

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        /// <summary>Analyzes mx records.</summary>
        public async Task AnalyzeMxRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "MX");
            // reset properties for repeated calls
            MxRecords = new List<string>();
            MxRecordTtls = Array.Empty<int>();
            MinMxTtl = null;
            MaxMxTtl = null;
            AvgMxTtl = null;
            MxRecordExists = false;
            PointsToCname = false;
            PointsToIpAddress = false;
            PointsToNonExistentDomain = false;
            PointsToDomainWithoutAOrAaaaRecord = false;
            PrioritiesInOrder = true;
            HasBackupServers = false;
            HasNullMx = false;
            PointsToLocalhost = false;
            Ipv6Supported = false;
            TtlsFromAuthoritativeServers = false;
            MxTtlUniform = true;
            MxRrsetConsistentAcrossNs = true;
            TargetAddressConsistentAcrossNs = true;

            if (dnsResults == null) {
                logger.WriteVerbose("DNS query returned no results.");
                return;
            }

            var mxRecordList = dnsResults.ToList();
            MxRecordExists = mxRecordList.Any();

            SetMxTtls(mxRecordList);

            var parsed = new List<(int Preference, string Host)>();
            foreach (var record in mxRecordList) {
                MxRecords.Add(record.Data);
                var parts = record.Data.Split(new[] { ' ' }, 2, System.StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && int.TryParse(parts[0], out var pref)) {
                    var host = parts[1].Trim('.');
                    if (pref == 0 && string.IsNullOrEmpty(host)) {
                        HasNullMx = true;
                        // Do not evaluate host lookups for null MX
                        continue;
                    }
                    parsed.Add((pref, host));
                    var lowerHost = host.ToLowerInvariant();
                    if (lowerHost == "localhost" || lowerHost == "localhost.localdomain" || lowerHost == "127.0.0.1") {
                        PointsToLocalhost = true;
                    }
                }
            }

            logger.WriteVerbose($"Analyzing MX records {string.Join(", ", MxRecords)}");

            var preferences = parsed.Select(p => p.Preference).ToList();
            if (preferences.Count > 1) {
                var stableSorted = parsed
                    .Select((p, index) => (p.Preference, index))
                    .OrderBy(p => p.Preference)
                    .ThenBy(p => p.index)
                    .Select(p => p.Preference)
                    .ToList();

                PrioritiesInOrder = preferences.SequenceEqual(stableSorted);
                HasBackupServers = preferences.Distinct().Count() > 1;
            }

            var evaluationList = parsed
                .GroupBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .Select(g => (Preference: g.Min(x => x.Preference), Host: g.Key))
                .OrderBy(p => p.Preference)
                .ToList();

            var hostsMissingAddress = new List<string>();
            foreach (var (_, host) in evaluationList) {
                var cnameResults = await QueryDns(host, DnsRecordType.CNAME);
                PointsToCname = PointsToCname || (cnameResults != null && cnameResults.Any());

                PointsToIpAddress = PointsToIpAddress || IPAddress.TryParse(host, out _);

                var aResults = await QueryDns(host, DnsRecordType.A);
                var aaaaResults = await QueryDns(host, DnsRecordType.AAAA);
                var noA = aResults == null || !aResults.Any();
                var noAAAA = aaaaResults == null || !aaaaResults.Any();
                Ipv6Supported = Ipv6Supported || !noAAAA;

                if (noA && noAAAA) {
                    var nsResults = await QueryDns(host, DnsRecordType.NS);
                    var nonExistent = nsResults == null || !nsResults.Any();
                    PointsToNonExistentDomain = PointsToNonExistentDomain || nonExistent;
                    PointsToDomainWithoutAOrAaaaRecord = PointsToDomainWithoutAOrAaaaRecord || !nonExistent;
                    if (!nonExistent) hostsMissingAddress.Add(host);
                }
            }
            // Emit assessments
            if (!MxRecordExists) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.Missing, "No MX records found for domain");
            }
            if (PointsToCname) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.CnameTarget, "One or more MX hostnames point to CNAMEs");
            }
            if (PointsToIpAddress) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.IpTarget, "MX record points directly to an IP address");
            }
            if (PointsToNonExistentDomain) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.TargetNonExistent, "One or more MX hostnames do not exist");
            }
            if (PointsToDomainWithoutAOrAaaaRecord) {
                foreach (var h in hostsMissingAddress) {
                    using (_collector.PushTarget(h))
                        logger.WriteWarningCode(MxCodes.TargetNoAddressRecords, "MX hostname has no A/AAAA records");
                }
            }
            if (!PrioritiesInOrder && evaluationList.Count > 1) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.PrioritiesOutOfOrder, "MX priorities are not in ascending stable order");
            }
            if (HasBackupServers) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteInformationCode(MxCodes.RedundantHosts, "Multiple MX preferences detected");
            } else if (evaluationList.Count >= 1 && !HasNullMx) {
                // Use provider detection to decide whether a single MX is acceptable for this provider.
                var hosts = evaluationList.Select(e => e.Host).ToList();
                var match = EmailProviderDetector.Detect(hosts);
                bool singleOk = match.Primary != null && match.Primary.SingleMxOk;
                if (!singleOk) {
                    using (_collector.PushTarget(Subject ?? string.Empty))
                        logger.WriteWarningCode(MxCodes.NoBackupServers, "Only a single MX preference detected; consider a backup MX");
                } else {
                    using (_collector.PushTarget(Subject ?? string.Empty))
                        logger.WriteInformationCode(MxCodes.SingleMxAllowedForProvider, $"Single MX acceptable for provider {match.Primary?.DisplayName}");
                }
            }
            if (HasNullMx) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.NullMxPresent, "Null MX present (0 .) indicates no inbound mail");
            }
            if (PointsToLocalhost) {
                using (_collector.PushTarget(Subject ?? string.Empty))
                    logger.WriteWarningCode(MxCodes.LocalhostTarget, "MX hostname points to localhost");
            }

            // TTLs are compared on authoritative answers only: a caching resolver reports the time left in its cache,
            // so the same zone would look uniform on one run and not on the next.
            DnsAnswer[]? authoritativeMx = await AuthoritativeMxAsync(mxRecordList);
            if (authoritativeMx is { Length: > 0 }) {
                TtlsFromAuthoritativeServers = true;
                SetMxTtls(authoritativeMx);
                if (authoritativeMx.Length > 1 && authoritativeMx.Select(r => r.TTL).Distinct().Count() > 1) {
                    MxTtlUniform = false;
                    using (_collector.PushTarget(Subject ?? string.Empty))
                        logger.WriteWarningCode(MxCodes.TtlNonUniform, "MX RRset TTLs differ across records");
                }
            }

            foreach (var (_, host) in evaluationList) {
                var a = await QueryAuthoritativeAsync(host, DnsRecordType.A);
                var aaaa = await QueryAuthoritativeAsync(host, DnsRecordType.AAAA);
                if (a == null && aaaa == null) {
                    logger.WriteVerbose("Skipping A/AAAA TTL comparison for {0}: no authoritative answer.", host);
                    continue;
                }
                var addrTtls = (a ?? Array.Empty<DnsAnswer>()).Concat(aaaa ?? Array.Empty<DnsAnswer>())
                    .Select(x => x.TTL).Distinct().ToList();
                if (addrTtls.Count > 1) {
                    using (_collector.PushTarget(host))
                        logger.WriteWarningCode(MxCodes.TargetTtlNonUniform, "A/AAAA TTLs differ for MX host");
                }
            }

            // Cross-NS RRset and address consistency (best-effort)
            try {
                if (!string.IsNullOrWhiteSpace(Subject)) {
                    await CheckCrossNsConsistencyAsync(Subject!, evaluationList.Select(e => e.Host), logger);
                }
            } catch (Exception ex) {
                logger.WriteDebug("MX cross-NS consistency check skipped: {0}", ex.Message);
            }
        }

        private void SetMxTtls(IEnumerable<DnsAnswer> answers) {
            int[] ttls = answers.Select(r => r.TTL).ToArray();
            MxRecordTtls = ttls;
            int[] positive = ttls.Where(static ttl => ttl > 0).ToArray();
            MinMxTtl = positive.Length > 0 ? positive.Min() : null;
            MaxMxTtl = positive.Length > 0 ? positive.Max() : null;
            AvgMxTtl = positive.Length > 0 ? positive.Average() : null;
        }

        private bool UsesFixedAnswers => QueryDnsOverride != null || DnsConfiguration.QueryDnsOverride != null;

        // The MX RRset as the zone publishes it. Fixed answers (tests, replays) already carry configured TTLs.
        private async Task<DnsAnswer[]?> AuthoritativeMxAsync(IReadOnlyList<DnsAnswer> resolverAnswers) {
            if (AuthoritativeQueryOverride == null && UsesFixedAnswers) return resolverAnswers.ToArray();
            if (string.IsNullOrWhiteSpace(Subject)) return null;
            return await QueryAuthoritativeAsync(Subject!, DnsRecordType.MX);
        }

        private readonly Dictionary<string, string?> _authoritativeServerByZone = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Answers of the given type from a name server authoritative for <paramref name="name"/>, or null when none
        /// answered authoritatively.
        /// </summary>
        private async Task<DnsAnswer[]?> QueryAuthoritativeAsync(string name, DnsRecordType type) {
            if (AuthoritativeQueryOverride != null) return await AuthoritativeQueryOverride(name, type);
            if (UsesFixedAnswers) return await QueryDns(name, type);
            try {
                string? server = await FindAuthoritativeServerAsync(name);
                if (server == null) return null;
                DnsResponse? response = await QueryViaServer(server, name, type);
                if (response == null || !response.IsAuthoritativeAnswer) return null;
                return (response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type).ToArray();
            } catch (Exception) {
                return null;
            }
        }

        // The zone of a name is the closest enclosing name with an NS set; one of its servers' addresses is used.
        private async Task<string?> FindAuthoritativeServerAsync(string name) {
            string candidate = NormalizeHost(name);
            while (candidate.IndexOf('.') > 0) {
                if (_authoritativeServerByZone.TryGetValue(candidate, out string? cached)) return cached;
                DnsAnswer[] nsAnswers = await QueryDns(candidate, DnsRecordType.NS) ?? Array.Empty<DnsAnswer>();
                string[] servers = nsAnswers.Where(a => a.Type == DnsRecordType.NS).Select(a => NormalizeHost(a.Data)).Where(h => h.Length > 0).OrderBy(h => h, StringComparer.Ordinal).ToArray();
                if (servers.Length > 0) {
                    string? address = null;
                    foreach (string server in servers) {
                        DnsAnswer[] a = await QueryDns(server, DnsRecordType.A) ?? Array.Empty<DnsAnswer>();
                        address = a.Where(x => x.Type == DnsRecordType.A).Select(x => x.Data).FirstOrDefault();
                        if (address != null) break;
                    }
                    _authoritativeServerByZone[candidate] = address;
                    return address;
                }
                candidate = candidate.Substring(candidate.IndexOf('.') + 1);
            }
            return null;
        }

        /// <summary>
        /// Validates MX record configuration based on collected analysis.
        /// </summary>
        /// <returns>
        /// <c>true</c> if configuration meets basic requirements; otherwise, <c>false</c>.
        /// </returns>
        public bool ValidMxConfiguration =>
            MxRecordExists
            && !PointsToCname
            && !PointsToIpAddress
            && !PointsToNonExistentDomain
            && !PointsToDomainWithoutAOrAaaaRecord;

        /// <summary>Validates mx configuration.</summary>
        public bool ValidateMxConfiguration() => ValidMxConfiguration;

        private static string NormalizeHost(string host) => (host ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

        private static string FormatMx(string data) {
            var parts = data.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && int.TryParse(parts[0], out var pref)) {
                return pref + " " + NormalizeHost(parts[1]);
            }
            return data?.Trim() ?? string.Empty;
        }

        private async Task CheckCrossNsConsistencyAsync(string domain, IEnumerable<string> mxHosts, InternalLogger logger) {
            if (DnsConfiguration.QueryDnsOverride != null) {
                logger.WriteVerbose("Skipping MX cross-NS consistency checks because DNS queries are running through an override.");
                return;
            }

            // Discover NS and their IPs
            var nsAnswers = await QueryDns(domain, DnsRecordType.NS) ?? Array.Empty<DnsAnswer>();
            var nsHosts = nsAnswers.Select(a => NormalizeHost(a.Data)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (nsHosts.Count == 0) return;
            var nsIps = new List<string>();
            foreach (var ns in nsHosts) {
                var a = await QueryDns(ns, DnsRecordType.A);
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA);
                nsIps.AddRange((a ?? Array.Empty<DnsAnswer>()).Select(x => x.Data));
                nsIps.AddRange((aaaa ?? Array.Empty<DnsAnswer>()).Select(x => x.Data));
            }
            nsIps = nsIps.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (nsIps.Count == 0) return;

            // Query each NS for MX RRset
            var mxByServer = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in nsIps) {
                var resp = await QueryViaServer(ip, domain, DnsRecordType.MX);
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var ans in resp?.Answers ?? Array.Empty<DnsAnswer>()) {
                    set.Add(FormatMx(ans.Data));
                }
                mxByServer[ip] = set;
            }
            if (mxByServer.Count > 1) {
                var first = mxByServer.First().Value;
                foreach (var kv in mxByServer.Skip(1)) {
                    if (!first.SetEquals(kv.Value)) {
                        MxRrsetConsistentAcrossNs = false;
                        using (AssessmentCollector.ForAnalysis(logger, this, category: "MX", target: domain))
                            logger.WriteWarningCode(MxCodes.RrsetInconsistentAcrossNs, "MX RRset differs across name servers");
                        break;
                    }
                }
            }

            // Query each NS for A/AAAA of each MX host
            foreach (var host in mxHosts.Select(NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase)) {
                var addrByServer = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
                foreach (var ip in nsIps) {
                    var aset = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var aResp = await QueryViaServer(ip, host, DnsRecordType.A);
                    var aaaaResp = await QueryViaServer(ip, host, DnsRecordType.AAAA);
                    foreach (var ans in aResp?.Answers ?? Array.Empty<DnsAnswer>()) aset.Add(ans.Data);
                    foreach (var ans in aaaaResp?.Answers ?? Array.Empty<DnsAnswer>()) aset.Add(ans.Data);
                    addrByServer[ip] = aset;
                }
                if (addrByServer.Count > 1) {
                    var firstAddr = addrByServer.First().Value;
                    foreach (var kv in addrByServer.Skip(1)) {
                        if (!firstAddr.SetEquals(kv.Value)) {
                            TargetAddressConsistentAcrossNs = false;
                            using (AssessmentCollector.ForAnalysis(logger, this, category: "MX", target: host))
                                logger.WriteWarningCode(MxCodes.TargetAddressInconsistentAcrossNs, "A/AAAA differs across name servers");
                            break;
                        }
                    }
                }
            }
        }

        private static async Task<DnsResponse?> QueryViaServer(string serverIp, string name, DnsRecordType type) {
            try {
                using var client = new ClientX(serverIp, DnsRequestFormat.DnsOverUDP, 53);
                client.EndpointConfiguration.UserAgent = DnsConfiguration.DefaultUserAgent;
                var resp = await client.Resolve(name, type);
                return resp;
            } catch {
                return null;
            }
        }
    }

}
