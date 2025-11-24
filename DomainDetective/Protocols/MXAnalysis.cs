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
        public string? Subject { get; set; }
        /// <summary>DNS configuration used for lookups.</summary>
        public DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>Optional DNS query override.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>MX records discovered during analysis.</summary>
        public List<string> MxRecords { get; private set; } = new List<string>();

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

        // Integrity checks
        public bool MxTtlUniform { get; private set; } = true;
        /// <summary>TTL values observed for MX RRset.</summary>
        public IReadOnlyList<int> MxRecordTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Minimum TTL across MX records.</summary>
        public int? MinMxTtl => (MxRecordTtls?.Count ?? 0) > 0 ? MxRecordTtls.Min() : null;
        public bool MxRrsetConsistentAcrossNs { get; private set; } = true;
        public bool TargetAddressConsistentAcrossNs { get; private set; } = true;

        /// <summary>Relevant standards for MX analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" },
            new StandardReference { Title = "Null MX for No Service", Reference = "RFC 7505", Url = "https://datatracker.ietf.org/doc/html/rfc7505" }
        };

        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        public async Task AnalyzeMxRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "MX") : null;
            // reset properties for repeated calls
            MxRecords = new List<string>();
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
            MxTtlUniform = true;
            MxRrsetConsistentAcrossNs = true;
            TargetAddressConsistentAcrossNs = true;
            MxRecordTtls = Array.Empty<int>();

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var mxRecordList = dnsResults.ToList();
            MxRecordExists = mxRecordList.Any();
            MxRecordTtls = mxRecordList.Select(r => r.TTL).ToArray();

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
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.Missing, "No MX records found for domain");
            }
            if (PointsToCname) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.CnameTarget, "One or more MX hostnames point to CNAMEs");
            }
            if (PointsToIpAddress) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.IpTarget, "MX record points directly to an IP address");
            }
            if (PointsToNonExistentDomain) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.TargetNonExistent, "One or more MX hostnames do not exist");
            }
            if (PointsToDomainWithoutAOrAaaaRecord) {
                foreach (var h in hostsMissingAddress) {
                    using (_collector?.PushTarget(h))
                        logger?.WriteWarningCode(MxCodes.TargetNoAddressRecords, "MX hostname has no A/AAAA records");
                }
            }
            if (!PrioritiesInOrder && evaluationList.Count > 1) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.PrioritiesOutOfOrder, "MX priorities are not in ascending stable order");
            }
            if (HasBackupServers) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteInformationCode(MxCodes.RedundantHosts, "Multiple MX preferences detected");
            } else if (evaluationList.Count >= 1 && !HasNullMx) {
                // Use provider detection to decide whether a single MX is acceptable for this provider.
                var hosts = evaluationList.Select(e => e.Host).ToList();
                var match = EmailProviderDetector.Detect(hosts);
                bool singleOk = match.Primary != null && match.Primary.SingleMxOk;
                if (!singleOk) {
                    using (_collector?.PushTarget(Subject ?? string.Empty))
                        logger?.WriteWarningCode(MxCodes.NoBackupServers, "Only a single MX preference detected; consider a backup MX");
                } else {
                    using (_collector?.PushTarget(Subject ?? string.Empty))
                        logger?.WriteInformationCode(MxCodes.SingleMxAllowedForProvider, $"Single MX acceptable for provider {match.Primary?.DisplayName}");
                }
            }
            if (HasNullMx) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.NullMxPresent, "Null MX present (0 .) indicates no inbound mail");
            }
            if (PointsToLocalhost) {
                using (_collector?.PushTarget(Subject ?? string.Empty))
                    logger?.WriteWarningCode(MxCodes.LocalhostTarget, "MX hostname points to localhost");
            }

            // TTL uniformity across MX RRset
            if (mxRecordList.Count > 1) {
                var ttls = mxRecordList.Select(r => r.TTL).Distinct().ToList();
                if (ttls.Count > 1) {
                    MxTtlUniform = false;
                    using (_collector?.PushTarget(Subject ?? string.Empty))
                        logger?.WriteWarningCode(MxCodes.TtlNonUniform, "MX RRset TTLs differ across records");
                }
            }

            // TTL uniformity across A/AAAA per MX host
            foreach (var (_, host) in evaluationList) {
                var a = await QueryDns(host, DnsRecordType.A);
                var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                var addrTtls = (a ?? Array.Empty<DnsAnswer>()).Concat(aaaa ?? Array.Empty<DnsAnswer>())
                    .Select(x => x.TTL).Distinct().ToList();
                if (addrTtls.Count > 1) {
                    using (_collector?.PushTarget(host))
                        logger?.WriteWarningCode(MxCodes.TargetTtlNonUniform, "A/AAAA TTLs differ for MX host");
                }
            }

            // Cross-NS RRset and address consistency (best-effort)
            try {
                if (!string.IsNullOrWhiteSpace(Subject)) {
                    await CheckCrossNsConsistencyAsync(Subject!, evaluationList.Select(e => e.Host), logger);
                }
            } catch (Exception ex) {
                logger?.WriteDebug("MX cross-NS consistency check skipped: {0}", ex.Message);
            }
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
                            logger?.WriteWarningCode(MxCodes.RrsetInconsistentAcrossNs, "MX RRset differs across name servers");
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
                                logger?.WriteWarningCode(MxCodes.TargetAddressInconsistentAcrossNs, "A/AAAA differs across name servers");
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
