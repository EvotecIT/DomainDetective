using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using System.Text.Json;

namespace DomainDetective {
    /// <summary>
    /// Performs analysis of NS records for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class NSAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Configuration used for DNS queries.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Allows injection of a DNS query implementation for testing.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Optional full DNS query override that returns raw responses.</summary>
        public Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }

        /// <summary>Optional override for recursion testing logic.</summary>
        public Func<string, Task<bool>>? RecursionTestOverride { private get; set; }
        /// <summary>Gets or sets the ns records value.</summary>
        public List<string> NsRecords { get; private set; } = new();
        /// <summary>Gets or sets the ns record exists value.</summary>
        public bool NsRecordExists { get; private set; }
        /// <summary>Gets or sets the has duplicates value.</summary>
        public bool HasDuplicates { get; private set; }
        /// <summary>Gets or sets the at least two records value.</summary>
        public bool AtLeastTwoRecords { get; private set; }
        /// <summary>Gets or sets the all have a or aaaa value.</summary>
        public bool AllHaveAOrAaaa { get; private set; }
        /// <summary>Gets or sets the points to cname value.</summary>
        public bool PointsToCname { get; private set; }
        /// <summary>Gets or sets the has diverse locations value.</summary>
        public bool HasDiverseLocations { get; private set; }
        /// <summary>Gets or sets the parent ns records value.</summary>
        public List<string> ParentNsRecords { get; private set; } = new();
        /// <summary>Gets or sets the delegation matches value.</summary>
        public bool DelegationMatches { get; private set; }
        /// <summary>Gets or sets the glue records complete value.</summary>
        public bool GlueRecordsComplete { get; private set; }
        /// <summary>Gets or sets the glue records consistent value.</summary>
        public bool GlueRecordsConsistent { get; private set; }

        /// <summary>Gets or sets the root server responses value.</summary>
        public Dictionary<string, bool> RootServerResponses { get; private set; } = new();
        /// <summary>Gets or sets the recursion enabled value.</summary>
        public Dictionary<string, bool> RecursionEnabled { get; private set; } = new();

        // CHAOS TXT fingerprinting (best-effort)
        /// <summary>Gets or sets the enable chaos fingerprinting value.</summary>
        public bool EnableChaosFingerprinting { get; set; } = true;
        /// <summary>Gets or sets the chaos query timeout ms value.</summary>
        public int ChaosQueryTimeoutMs { get; set; } = 2500;
        /// <summary>Gets or sets the chaos max server ips to query value.</summary>
        public int ChaosMaxServerIpsToQuery { get; set; } = 10;
        /// <summary>Gets or sets the chaos version by server value.</summary>
        public Dictionary<string, string> ChaosVersionByServer { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets or sets the chaos hostname by server value.</summary>
        public Dictionary<string, string> ChaosHostnameByServer { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Optional parsed-response override for direct CHAOS-class probes.</summary>
        public Func<IPAddress, DnsMessage, CancellationToken, Task<DnsResponse?>>? QueryResponseOverride { get; set; }

        // ASN diversity (provider diversity)
        /// <summary>Gets or sets the asn by ip value.</summary>
        public Dictionary<string, int> AsnByIp { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets or sets the asn distinct count value.</summary>
        public int AsnDistinctCount { get; private set; }

        /// <summary>Override for ASN lookup in tests.</summary>
        public Func<string, Task<int?>>? LookupAsnOverride { private get; set; }

        /// <summary>Timeout (ms) for best-effort ASN lookups when no override is set.</summary>
        public int AsnLookupTimeoutMs { get; set; } = 5000;

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();

        /// <summary>
        /// Executes a DNS query for the specified record type.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            var queryDnsOverride = QueryDnsOverride;
            if (queryDnsOverride != null) {
                // Try exact first
                var res = await queryDnsOverride(name, type);
                if (res != null && res.Length > 0) return res;
                // Fallback to toggling trailing dot to accommodate tests and mixed data
                string alt = name.EndsWith(".", StringComparison.Ordinal) ? name.TrimEnd('.') : name + ".";
                try { res = await queryDnsOverride(alt, type); } catch { res = Array.Empty<DnsAnswer>(); }
                return res ?? Array.Empty<DnsAnswer>();
            }

            return await DnsConfiguration.QueryDNS(name, type) ?? Array.Empty<DnsAnswer>();
        }

        private async Task<IEnumerable<DnsResponse>> QueryFullDns(string name, DnsRecordType type) {
            var queryDnsFullOverride = QueryDnsFullOverride;
            if (queryDnsFullOverride != null) {
                return await queryDnsFullOverride(name, type);
            }

            return await DnsConfiguration.QueryFullDNS(new[] { name }, type) ?? Array.Empty<DnsResponse>();
        }

        private static string? GetParentZone(string domain) {
            if (string.IsNullOrWhiteSpace(domain) || !domain.Contains('.')) {
                return null;
            }
            var parts = domain.Trim('.').Split('.');
            return parts.Length > 1 ? string.Join(".", parts.Skip(1)) : null;
        }

        private static bool AnswersMatch(IEnumerable<DnsAnswer>? first, IEnumerable<DnsAnswer>? second) {
            var a = new HashSet<string>(first?.Select(f => f.Data) ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var b = new HashSet<string>(second?.Select(s => s.Data) ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            return a.SetEquals(b);
        }

        /// <summary>
        /// Queries the parent zone for NS records and glue information.
        /// </summary>
        public async Task<(List<string> NsRecords, Dictionary<string, List<string>> GlueRecords)> QueryParentNsGlue(string domainName, InternalLogger logger) {
            List<string> nsRecords = new();
            Dictionary<string, List<string>> glueRecords = new(StringComparer.OrdinalIgnoreCase);

            var responses = (await QueryFullDns(domainName, DnsRecordType.NS)).ToArray();
            if (responses.Length == 0) {
                return (nsRecords, glueRecords);
            }

            var response = responses[0];
            foreach (var rec in response.Answers ?? Array.Empty<DnsAnswer>()) {
                nsRecords.Add(rec.Data.Trim('.'));
            }

            foreach (var add in response.Additional ?? Array.Empty<DnsAnswer>()) {
                if (add.Type == DnsRecordType.A || add.Type == DnsRecordType.AAAA) {
                    var host = add.Name.Trim('.');
                    if (!glueRecords.TryGetValue(host, out var list)) {
                        list = new List<string>();
                        glueRecords[host] = list;
                    }
                    list.Add(add.Data);
                }
            }

            return (nsRecords, glueRecords);
        }

        /// <summary>
        /// Processes NS records and determines their properties.
        /// </summary>
        public async Task AnalyzeNsRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "NS");
            NsRecords = new List<string>();
            NsRecordExists = false;
            HasDuplicates = false;
            AtLeastTwoRecords = false;
            AllHaveAOrAaaa = true;
            PointsToCname = false;
            HasDiverseLocations = false;
            ChaosVersionByServer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ChaosHostnameByServer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (dnsResults == null) {
                logger.WriteVerbose("DNS query returned no results.");
                return;
            }

            var nsList = dnsResults.ToList();
            NsRecordExists = nsList.Any();
            AtLeastTwoRecords = nsList.Count >= 2;

            var missingAddressHosts = new List<string>();
            foreach (var record in nsList) {
                var host = record.Data.Trim('.');
                NsRecords.Add(host);
            }

            HasDuplicates = NsRecords.Count != NsRecords.Distinct(StringComparer.OrdinalIgnoreCase).Count();

            HashSet<string> subnets = new(StringComparer.OrdinalIgnoreCase);

            var allIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var nsIps = new List<(string Host, IPAddress Ip)>();
            foreach (var ns in NsRecords) {
                var cname = await QueryDns(ns, DnsRecordType.CNAME);
                PointsToCname = PointsToCname || (cname != null && cname.Any());

                var a = await QueryDns(ns, DnsRecordType.A);
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA);
                if ((a == null || !a.Any()) && (aaaa == null || !aaaa.Any())) {
                    AllHaveAOrAaaa = false;
                    missingAddressHosts.Add(ns);
                }

                foreach (var answer in a ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                        allIps.Add(ip.ToString());
                        nsIps.Add((ns, ip));
                    }
                }

                foreach (var answer in aaaa ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                        allIps.Add(ip.ToString());
                        nsIps.Add((ns, ip));
                    }
                }
            }

            // ASN lookups (best-effort)
            AsnByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var asnLookupTimeoutMs = AsnLookupTimeoutMs > 0 ? AsnLookupTimeoutMs : 5000;
            foreach (var ip in allIps)
            {
                try {
                    int? asn;
                    if (LookupAsnOverride != null) {
                        asn = await LookupAsnOverride(ip);
                    } else {
                        using var cts = new CancellationTokenSource(asnLookupTimeoutMs);
                        asn = await LookupAsnAsync(ip, cts.Token);
                    }
                    if (asn.HasValue) {
                        AsnByIp[ip] = asn.Value;
                    }
                } catch { /* ignore lookup failures */ }
            }
            AsnDistinctCount = AsnByIp.Values.Distinct().Count();

            HasDiverseLocations = subnets.Count >= 2 || AsnDistinctCount >= 2;

            // Emit assessments for common NS issues
            if (!NsRecordExists) {
                logger.WriteWarningCode(NSCodes.Missing, "No NS records found");
            }
            if (HasDuplicates) {
                logger.WriteWarningCode(NSCodes.Duplicate, "Duplicate NS records detected");
            }
            if (!AtLeastTwoRecords) {
                logger.WriteWarningCode(NSCodes.TooFewRecords, "Fewer than two NS records published");
            }
            if (PointsToCname) {
                logger.WriteWarningCode(NSCodes.CnameTarget, "One or more NS hostnames point to CNAMEs");
            }
            if (!AllHaveAOrAaaa) {
                foreach (var host in missingAddressHosts) {
                    using (_collector.PushTarget(host))
                        logger.WriteWarningCode(NSCodes.MissingAddressRecords, "NS hostname has no A/AAAA address records");
                }
            }
            if (!HasDiverseLocations) {
                logger.WriteWarningCode(NSCodes.LowDiversity, "NS hosts lack diversity across networks");
            } else {
                // Surface a clear positive that highlights ASN/vendor diversity explicitly
                logger.WriteInformationCode(NSCodes.HighDiversity, $"Authoritative NS are diverse across networks/providers (ASNs: {AsnDistinctCount})");
            }

            // Best-effort CHAOS TXT fingerprinting for version/hostname disclosure
            if (DnsConfiguration.QueryDnsOverride == null) {
                try
                {
                    await FingerprintChaosAsync(nsIps, logger, _collector, CancellationToken.None);
                }
                catch
                {
                }
            } else {
                logger.WriteVerbose("Skipping CHAOS fingerprinting because DNS queries are running through an override.");
            }
        }

        private static async Task<int?> LookupAsnAsync(string ip, CancellationToken ct)
        {
            try {
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, $"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}");
                using var response = await SharedHttpClient.Instance.SendAsync(req, ct).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
#if NET8_0_OR_GREATER
                var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
#else
                var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream).ConfigureAwait(false);
#endif
                if (!doc.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("asns", out var asns)) return null;
                if (asns.ValueKind != JsonValueKind.Array || asns.GetArrayLength() == 0) return null;
                var first = asns[0];
                if (first.TryGetProperty("asn", out var asnProp)) return asnProp.GetInt32();
                return null;
            } catch { return null; }
        }

        /// <summary>
        /// Analyzes delegation information from the parent zone.
        /// </summary>
        /// <param name="domainName">Domain being checked.</param>
        /// <param name="logger">Logger used for diagnostics.</param>
        public async Task AnalyzeParentDelegation(string domainName, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "NS", target: domainName);
            ParentNsRecords = new List<string>();
            DelegationMatches = false;
            GlueRecordsComplete = true;
            GlueRecordsConsistent = true;

            var parent = GetParentZone(domainName);
            if (string.IsNullOrEmpty(parent)) {
                logger.WriteVerbose("No parent zone for {0}", domainName);
                return;
            }

            var (parentNs, glue) = await QueryParentNsGlue(domainName, logger);
            ParentNsRecords = parentNs;

            if (!ParentNsRecords.Any()) {
                GlueRecordsComplete = false;
                return;
            }

            DelegationMatches = new HashSet<string>(ParentNsRecords, StringComparer.OrdinalIgnoreCase)
                .SetEquals(NsRecords);

            foreach (var ns in ParentNsRecords) {
                if (!ns.EndsWith('.' + domainName, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                glue.TryGetValue(ns, out var parentGlue);
                if (parentGlue == null || parentGlue.Count == 0) {
                    GlueRecordsComplete = false;
                    continue;
                }

                var childA = await QueryDns(ns, DnsRecordType.A);
                var childAaaa = await QueryDns(ns, DnsRecordType.AAAA);
                var combined = childA.Concat(childAaaa ?? Array.Empty<DnsAnswer>()).Select(a => a.Data);
                if (!new HashSet<string>(parentGlue, StringComparer.OrdinalIgnoreCase).SetEquals(combined)) {
                    GlueRecordsConsistent = false;
                }
            }

            if (!DelegationMatches) {
                logger.WriteWarningCode(NSCodes.DelegationMismatch, "Parent delegation NS set differs from child zone NS set");
            }
            if (!GlueRecordsComplete) {
                logger.WriteWarningCode(NSCodes.GlueIncomplete, "Parent zone missing glue records for in-bailiwick NS");
            }
            if (!GlueRecordsConsistent) {
                logger.WriteWarningCode(NSCodes.GlueInconsistent, "Parent glue records do not match child A/AAAA records");
            }
        }

        /// <summary>Executes the query root servers operation.</summary>
        public async Task QueryRootServers(InternalLogger logger) {
            RootServerResponses = new Dictionary<string, bool>();
            var roots = await QueryDns(".", DnsRecordType.NS);
            foreach (var root in roots) {
                var host = root.Data.Trim('.');
                bool responsive = false;
                try {
                    var a = await QueryDns(host, DnsRecordType.A);
                    if (a != null && a.Any()) {
                        responsive = true;
                    } else {
                        var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                        responsive = aaaa != null && aaaa.Any();
                    }
                } catch {
                    responsive = false;
                }
                RootServerResponses[host] = responsive;
            }
        }

        /// <summary>Executes the test recursion operation.</summary>
        public async Task TestRecursion(InternalLogger logger) {
            RecursionEnabled = new Dictionary<string, bool>();
            foreach (var ns in NsRecords) {
                var host = ns.Trim('.');
                bool recursion = await CheckRecursionAsync(host, logger);
                RecursionEnabled[host] = recursion;
                if (recursion) {
                    using var _s = AssessmentCollector.ForAnalysis(logger, this, category: "NS", target: host);
                    logger.WriteWarningCode(NSCodes.RecursionOnAuthoritative, "Authoritative NS allows recursion");
                }
            }
        }

        private async Task<string?> QueryChaosTxtAsync(IPAddress server, string name, InternalLogger logger, CancellationToken token)
        {
            try
            {
                var timeout = ChaosQueryTimeoutMs > 0 ? ChaosQueryTimeoutMs : 2500;
                var query = new DnsMessage(name, DnsRecordType.TXT, new DnsMessageOptions(
                    RecursionDesired: false,
                    QueryClass: 3));
                DnsResponse? response;
                if (QueryResponseOverride != null) {
                    response = await QueryResponseOverride(server, query, token).ConfigureAwait(false);
                } else {
                    DnsWireQueryResult result = await DnsWireQueryClient.QueryUdpAsync(
                        server.ToString(), 53, query, timeout, useTcpFallback: true, cancellationToken: token).ConfigureAwait(false);
                    response = result.Response;
                }
                return (response?.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == DnsRecordType.TXT)
                    .Select(answer => answer.Data ?? answer.DataRaw)
                    .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger?.WriteVerbose("CHAOS TXT query failed for {0} on {1}: {2}", name, server, ex.Message);
                return null;
            }
        }

        private async Task FingerprintChaosAsync(IEnumerable<(string Host, IPAddress Ip)> servers, InternalLogger logger, AssessmentCollector collector, CancellationToken token)
        {
            if (!EnableChaosFingerprinting)
            {
                return;
            }

            var limit = ChaosMaxServerIpsToQuery <= 0 ? 0 : ChaosMaxServerIpsToQuery;
            if (limit == 0)
            {
                return;
            }

            var list = (servers ?? Array.Empty<(string Host, IPAddress Ip)>())
                .Where(s => s.Ip != null)
                .Select(s => (s.Host, s.Ip, Key: $"{s.Host} ({s.Ip})"))
                .Distinct()
                .Take(limit)
                .ToList();

            foreach (var s in list)
            {
                token.ThrowIfCancellationRequested();

                var version = await QueryChaosTxtAsync(s.Ip, "version.bind", logger, token);
                if (version != null)
                {
                    var trimmed = version.Trim();
                    if (trimmed.Length > 0)
                    {
                        ChaosVersionByServer[s.Key] = trimmed;
                        using (collector.PushTarget(s.Key))
                            logger.WriteWarningCode(NSCodes.ChaosVersionExposed, "CHAOS version.bind exposed: {0}", trimmed);
                    }
                }

                var hostname = await QueryChaosTxtAsync(s.Ip, "hostname.bind", logger, token);
                if (hostname != null)
                {
                    var trimmed = hostname.Trim();
                    if (trimmed.Length > 0)
                    {
                        ChaosHostnameByServer[s.Key] = trimmed;
                        using (collector.PushTarget(s.Key))
                            logger.WriteWarningCode(NSCodes.ChaosHostnameExposed, "CHAOS hostname.bind exposed: {0}", trimmed);
                    }
                }
            }
        }

        private async Task<bool> CheckRecursionAsync(string server, InternalLogger logger) {
            var recursionTestOverride = RecursionTestOverride;
            if (recursionTestOverride != null) {
                return await recursionTestOverride(server);
            }
            try {
                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
                var query = new DnsMessage("example.com", DnsRecordType.A, new DnsMessageOptions(RecursionDesired: true));
                DnsWireQueryResult result = await DnsWireQueryClient.QueryUdpAsync(
                    server, 53, query, 5000, useTcpFallback: false, cancellationToken: cts.Token).ConfigureAwait(false);
                return result.Response.IsRecursionAvailable;
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger.WriteVerbose("Recursion test failed for {0}: {1}", server, ex.Message);
                return false;
            }
        }
    }
}
