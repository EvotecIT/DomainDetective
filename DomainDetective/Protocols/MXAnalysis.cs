using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
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
    public partial class MXAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>DNS configuration used for lookups.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>MX records discovered during analysis.</summary>
        public List<string> MxRecords { get; private set; } = new List<string>();

        /// <summary>
        /// TTL values (seconds) for each MX record answer as returned by DNS.
        /// </summary>
        /// <remarks>
        /// MX commonly returns multiple answers; this analysis exposes both the raw TTL set and aggregate
        /// min/avg/max values to support operational TTL policy checks without additional DNS queries.
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
        /// <summary>True when at least one MX target's CNAME query could not complete.</summary>
        public bool CnameQueryFailed { get; private set; }

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
        /// <summary>Gets or sets the mx ttl uniform value.</summary>
        public bool MxTtlUniform { get; private set; } = true;
        /// <summary>Gets or sets the mx rrset consistent across ns value.</summary>
        public bool MxRrsetConsistentAcrossNs { get; private set; } = true;
        /// <summary>Gets or sets the target address consistent across ns value.</summary>
        public bool TargetAddressConsistentAcrossNs { get; private set; } = true;
        /// <summary>Whether unavailable authoritative responses prevented complete MX address comparison.</summary>
        public bool TargetAddressComparisonIncomplete { get; private set; }
        /// <summary>Whether authoritative MX RRset replies were missing from the comparison.</summary>
        public bool MxRrsetComparisonIncomplete { get; private set; } = true;

        /// <summary>Relevant standards for MX analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" },
            new StandardReference { Title = "Null MX for No Service", Reference = "RFC 7505", Url = "https://datatracker.ietf.org/doc/html/rfc7505" }
        };

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken = default) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type).WaitWithCancellation(cancellationToken);
            }

            return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken);
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
            CnameQueryFailed = false;
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
            MxRrsetComparisonIncomplete = true;
            TargetAddressConsistentAcrossNs = true;
            TargetAddressComparisonIncomplete = true;

            if (dnsResults == null) {
                logger.WriteVerbose("DNS query returned no results.");
                return;
            }

            var mxRecordList = dnsResults.ToList();
            MxRecordExists = mxRecordList.Any();

            var ttlArray = mxRecordList.Select(r => r.TTL).ToArray();
            MxRecordTtls = ttlArray;
            int? minTtl = null;
            int? maxTtl = null;
            long sumTtl = 0;
            int positiveCount = 0;
            foreach (var ttl in ttlArray) {
                if (ttl <= 0) {
                    continue;
                }

                positiveCount++;
                sumTtl += ttl;
                if (!minTtl.HasValue || ttl < minTtl.Value) {
                    minTtl = ttl;
                }
                if (!maxTtl.HasValue || ttl > maxTtl.Value) {
                    maxTtl = ttl;
                }
            }

            if (positiveCount > 0) {
                MinMxTtl = minTtl;
                MaxMxTtl = maxTtl;
                AvgMxTtl = (double)sumTtl / positiveCount;
            }

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

            CnameQueryFailed = false;
            var hostsMissingAddress = new List<string>();
            var cnameResults = await DomainDetective.Helpers.AuthoritativeDnsProbes.RunAsync(evaluationList, async item => {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                DnsAnswer[] cnames;
                bool cnameSucceeded = true;
                try {
                    if (QueryDnsOverride != null) {
                        cnames = await QueryDns(item.Host, DnsRecordType.CNAME, deadline.Token);
                    } else {
                        var response = await DnsConfiguration.QueryDNSResponse(item.Host, DnsRecordType.CNAME, cancellationToken: deadline.Token);
                        cnameSucceeded = string.IsNullOrEmpty(response.Error) &&
                            (response.Status == DnsResponseCode.NoError || response.Status == DnsResponseCode.NXDomain);
                        cnames = cnameSucceeded ? response.Answers ?? Array.Empty<DnsAnswer>() : Array.Empty<DnsAnswer>();
                    }
                    deadline.Token.ThrowIfCancellationRequested();
                } catch (Exception ex) when (ex is OperationCanceledException && deadline.IsCancellationRequested || ex is TimeoutException || ex is System.Net.Sockets.SocketException) {
                    cnames = Array.Empty<DnsAnswer>();
                    cnameSucceeded = false;
                }
                return (item.Host, Cnames: cnames, CnameSucceeded: cnameSucceeded);
            });
            // Complete bounded alias checks before adding competing address work to the resolver queue.
            var hostResults = await DomainDetective.Helpers.AuthoritativeDnsProbes.RunAsync(cnameResults, async item => {
                var aTask = QueryDns(item.Host, DnsRecordType.A);
                var aaaaTask = QueryDns(item.Host, DnsRecordType.AAAA);
                await Task.WhenAll(aTask, aaaaTask);
                var ns = aTask.Result.Length == 0 && aaaaTask.Result.Length == 0
                    ? await QueryDns(item.Host, DnsRecordType.NS) : Array.Empty<DnsAnswer>();
                return (item.Host, item.Cnames, item.CnameSucceeded, A: aTask.Result, Aaaa: aaaaTask.Result, Ns: ns);
            });
            foreach (var item in hostResults) {
                var host = item.Host;
                if (!item.CnameSucceeded) {
                    CnameQueryFailed = true;
                    logger.WriteWarningCode("MX.Cname.QueryFailed", "CNAME query for MX target {0} did not complete; alias status is unknown.", host);
                }
                PointsToCname = PointsToCname || item.Cnames.Any();
                PointsToIpAddress = PointsToIpAddress || IPAddress.TryParse(host, out _);
                var noA = item.A.Length == 0;
                var noAAAA = item.Aaaa.Length == 0;
                Ipv6Supported = Ipv6Supported || !noAAAA;
                if (noA && noAAAA) {
                    var nonExistent = item.Ns.Length == 0;
                    PointsToNonExistentDomain = PointsToNonExistentDomain || nonExistent;
                    PointsToDomainWithoutAOrAaaaRecord = PointsToDomainWithoutAOrAaaaRecord || !nonExistent;
                    if (!nonExistent) { hostsMissingAddress.Add(host); }
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

            // TTL uniformity across MX RRset
            if (mxRecordList.Count > 1) {
                var ttls = mxRecordList.Select(r => r.TTL).Distinct().ToList();
                if (ttls.Count > 1) {
                    MxTtlUniform = false;
                    using (_collector.PushTarget(Subject ?? string.Empty))
                        logger.WriteWarningCode(MxCodes.TtlNonUniform, "MX RRset TTLs differ across records");
                }
            }

            // TTL uniformity across A/AAAA per MX host
            foreach (var (_, host) in evaluationList) {
                var a = await QueryDns(host, DnsRecordType.A);
                var aaaa = await QueryDns(host, DnsRecordType.AAAA);
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

        /// <summary>
        /// Validates MX record configuration based on collected analysis.
        /// </summary>
        /// <returns>
        /// <c>true</c> if configuration meets basic requirements; otherwise, <c>false</c>.
        /// </returns>
        public bool ValidMxConfiguration =>
            MxRecordExists
            && !CnameQueryFailed
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
            var mxResponses = await DomainDetective.Helpers.AuthoritativeDnsProbes.RunAsync(nsIps, async ip => (Ip: ip, Response: await QueryViaServer(ip, domain, DnsRecordType.MX)));
            foreach (var item in mxResponses) {
                var ip = item.Ip;
                var resp = item.Response;
                if (resp == null) { continue; }
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var ans in resp?.Answers ?? Array.Empty<DnsAnswer>()) {
                    set.Add(FormatMx(ans.Data));
                }
                mxByServer[ip] = set;
            }
            DomainDetective.Helpers.AuthoritativeDnsProbes.ReportIpv6Reachability(nsIps, mxByServer.Keys, logger);
            RecordRrsetCompleteness(nsIps.Count, mxByServer.Count, domain, logger);
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
            TargetAddressComparisonIncomplete = mxByServer.Count < nsIps.Count;
            foreach (var host in mxHosts.Select(NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase)) {
                var addressResponses = await DomainDetective.Helpers.AuthoritativeDnsProbes.RunAsync(mxByServer.Keys, async ip => {
                    var aTask = QueryViaServer(ip, host, DnsRecordType.A);
                    var aaaaTask = QueryViaServer(ip, host, DnsRecordType.AAAA);
                    await Task.WhenAll(aTask, aaaaTask);
                    return (Ip: ip, A: aTask.Result, Aaaa: aaaaTask.Result);
                });
                RecordTargetAddressEvidence(host, addressResponses.Select(item => (item.A, item.Aaaa)), logger);
            }
        }

        private static Task<DnsResponse?> QueryViaServer(string serverIp, string name, DnsRecordType type)
            => DomainDetective.Helpers.AuthoritativeDnsProbes.QueryAsync(serverIp, name, type);

    }

}
