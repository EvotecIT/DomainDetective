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
    /// <remarks>
    /// Typical TTL thresholds are based on operational best practices and may
    /// be adjusted to suit specific environments.
    /// </remarks>
    public partial class DnsTtlAnalysis : IHasAssessments {
        private readonly List<string> _warnings = new();
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }

        /// <summary>
        /// Indicates whether the zone is signed with DNSSEC.
        /// </summary>
        public bool DnsSecSigned { get; private set; }

        /// <summary>Gets TTL values for A records including zero values.</summary>
        public IReadOnlyList<int> ATtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for AAAA records including zero values.</summary>
        public IReadOnlyList<int> AaaaTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for MX records including zero values.</summary>
        public IReadOnlyList<int> MxTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for NS records including zero values.</summary>
        public IReadOnlyList<int> NsTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets the TTL value for the SOA record; zero indicates no TTL or missing record.</summary>
        public int SoaTtl { get; private set; }
        /// <summary>TTL values for SPF TXT at the zone apex.</summary>
        public IReadOnlyList<int> SpfTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _dmarc TXT.</summary>
        public IReadOnlyList<int> DmarcTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _mta-sts TXT.</summary>
        public IReadOnlyList<int> MtastsTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _smtp._tls TXT (TLS-RPT).</summary>
        public IReadOnlyList<int> TlsRptTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for DKIM selector TXT records, keyed by FQDN (selector._domainkey.domain).</summary>
        public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; private set; } = new();
        /// <summary>Collection of warning messages produced during analysis.</summary>
        public IReadOnlyList<string> Warnings => _warnings;

        /// <summary>Structured assessments captured during TTL analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
        /// <summary>Whether the authoritative TTL comparison lacks a value for any intended server or record set.</summary>
        public bool UniformityIncomplete { get; private set; }

        /// <summary>Provides DNS query implementation details.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
        /// <summary>Optional list of DKIM selectors discovered earlier (used for TXT TTL checks).</summary>
        public List<string> DkimSelectors { get; set; } = new();
        /// <summary>Minimum TTL for SPF TXT records (seconds).</summary>
        public int MinTtlSpfSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for DMARC TXT records (seconds).</summary>
        public int MinTtlDmarcSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for DKIM selector TXT records (seconds).</summary>
        public int MinTtlDkimSelectorSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for MTA-STS TXT records (seconds).</summary>
        public int MinTtlMtastsSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for TLS-RPT TXT records (seconds).</summary>
        public int MinTtlTlsRptSeconds { get; set; } = 3600;

        /// <summary>
        /// UDP receive timeout (milliseconds) used when querying authoritative servers directly
        /// during <see cref="AnalyzeUniformityAcrossServers"/>.
        /// </summary>
        public int UniformityQueryTimeoutMs { get; set; } = 4000;

        /// <summary>
        /// Maximum number of concurrent authoritative-server TTL queries performed by
        /// <see cref="AnalyzeUniformityAcrossServers"/>.
        /// </summary>
        public int UniformityMaxParallelism { get; set; } = 16;

	        // Per-authoritative-server TTL uniformity results
	        /// <summary>Gets or sets the server ttl a value.</summary>
	        public Dictionary<string, int?> ServerTtlA { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl aaaa value.</summary>
	        public Dictionary<string, int?> ServerTtlAaaa { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl ns value.</summary>
	        public Dictionary<string, int?> ServerTtlNs { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl cname value.</summary>
	        public Dictionary<string, int?> ServerTtlCname { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl txt spf value.</summary>
	        public Dictionary<string, int?> ServerTtlTxtSpf { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl txt dmarc value.</summary>
	        public Dictionary<string, int?> ServerTtlTxtDmarc { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl txt mtasts value.</summary>
	        public Dictionary<string, int?> ServerTtlTxtMtasts { get; private set; } = new();
	        /// <summary>Gets or sets the server ttl txt tls rpt value.</summary>
	        public Dictionary<string, int?> ServerTtlTxtTlsRpt { get; private set; } = new();
	        /// <summary>Per-name TXT TTLs across authoritative servers. Key is the record name (e.g., s1._domainkey.example.com).</summary>
	        public Dictionary<string, Dictionary<string, int?>> ServerTtlTxtPerName { get; private set; } = new();
	        /// <summary>Gets or sets the a uniform across servers value.</summary>
	        public bool AUniformAcrossServers { get; private set; }
	        /// <summary>Gets or sets the aaaa uniform across servers value.</summary>
	        public bool AaaaUniformAcrossServers { get; private set; }
	        /// <summary>Gets or sets the ns uniform across servers value.</summary>
	        public bool NsUniformAcrossServers { get; private set; }
        /// <summary>Gets or sets the cname uniform across servers value.</summary>
        public bool CnameUniformAcrossServers { get; private set; }

        /// <summary>
        /// Optional override for DNS queries, primarily used for testing.
        /// </summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        private readonly Func<System.Net.IPAddress, string, DnsRecordType, int, System.Threading.CancellationToken, bool, Task<DnsResponse?>> _queryAuthoritative;

        /// <summary>Creates TTL analysis using the native DNS wire transport.</summary>
        public DnsTtlAnalysis() : this(QueryAuthoritativeAsync) { }

        /// <summary>Supplies the authoritative transport boundary without changing recursive discovery.</summary>
        internal DnsTtlAnalysis(Func<System.Net.IPAddress, string, DnsRecordType, int, System.Threading.CancellationToken, bool, Task<DnsResponse?>> queryAuthoritative) {
            _queryAuthoritative = queryAuthoritative ?? throw new ArgumentNullException(nameof(queryAuthoritative));
        }

        private static async Task<DnsResponse?> QueryAuthoritativeAsync(System.Net.IPAddress ip, string name,
            DnsRecordType type, int timeoutMs, System.Threading.CancellationToken ct, bool preflight) {
            if (preflight) {
                return await Helpers.AuthoritativeDnsProbes.QueryAsync(ip.ToString(), name, type, timeoutMs, ct, acceptRefused: true).ConfigureAwait(false);
            }
            return await Helpers.AuthoritativeDnsProbes.QueryAsync(ip.ToString(), name, type, timeoutMs, ct).ConfigureAwait(false);
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, System.Threading.CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            if (QueryDnsOverride != null) {
                var answers = await QueryDnsOverride(name, type);
                ct.ThrowIfCancellationRequested();
                return answers;
            }

            if (type == DnsRecordType.TXT) {
                return await DnsConfiguration.QueryDNS(
                    name,
                    type,
                    filter: string.Empty,
                    includeAliasesInFilter: true, cancellationToken: ct);
            }
            return await DnsConfiguration.QueryDNS(name, type, cancellationToken: ct);
        }

        private async Task<(int? Ttl, bool Succeeded)> QueryTtlFromServer(System.Net.IPAddress ip, string name, ushort qtype, System.Threading.CancellationToken ct, int timeoutMs) {
            var response = await _queryAuthoritative(ip, name, (DnsRecordType)qtype, timeoutMs > 0 ? timeoutMs : 4000, ct, false).ConfigureAwait(false);
            return ReadAuthoritativeTtl(response, (DnsRecordType)qtype);
        }

        private static (int? Ttl, bool Succeeded) ReadAuthoritativeTtl(DnsResponse? response, DnsRecordType type) {
            if (!DomainDetective.Helpers.AuthoritativeDnsProbes.IsAuthoritativeResponse(response)) { return (null, false); }
            var answers = response!.Answers ?? Array.Empty<DnsAnswer>();
            int? answerTtl = answers
                .Where(item => item.Type == type)
                .Select(item => (int?)item.TTL)
                .FirstOrDefault();
            if (answerTtl.HasValue) return (answerTtl, true);
            return (answers
                .Where(item => item.Type == DnsRecordType.CNAME)
                .Select(item => (int?)item.TTL)
                .FirstOrDefault(), true);
        }

        /// <summary>
        /// Queries DNS records for TTL values and evaluates them.
        /// </summary>
        /// <param name="domainName">Domain name to analyze.</param>
        /// <param name="logger">Optional logger used for diagnostics.</param>
        public Task Analyze(string domainName, InternalLogger logger)
            => Analyze(domainName, logger, System.Threading.CancellationToken.None);

        /// <summary>Queries independent TTL prerequisites with bounded concurrency and caller cancellation.</summary>
        public async Task Analyze(string domainName, InternalLogger logger, System.Threading.CancellationToken ct) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNS", target: domainName);
            Subject = domainName;
            UniformityIncomplete = false;
            TtlsFromAuthoritativeServers = false;
            _authoritativeTtlLabels.Clear();
            _warnings.Clear();
            ATtls = Array.Empty<int>();
            AaaaTtls = Array.Empty<int>();
            MxTtls = Array.Empty<int>();
            NsTtls = Array.Empty<int>();
            SoaTtl = 0;
            SpfTxtTtls = Array.Empty<int>();
            DmarcTxtTtls = Array.Empty<int>();
            MtastsTxtTtls = Array.Empty<int>();
            TlsRptTxtTtls = Array.Empty<int>();
            DkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>();

            var requests = new[] {
                (domainName, DnsRecordType.A), (domainName, DnsRecordType.AAAA),
                (domainName, DnsRecordType.MX), (domainName, DnsRecordType.NS),
                (domainName, DnsRecordType.SOA), (domainName, DnsRecordType.DS),
                (domainName, DnsRecordType.TXT), ($"_dmarc.{domainName}", DnsRecordType.TXT),
                ($"_mta-sts.{domainName}", DnsRecordType.TXT), ($"_smtp._tls.{domainName}", DnsRecordType.TXT)
            };
            var records = await Helpers.AuthoritativeDnsProbes.RunAsync(requests,
                request => QueryDns(request.Item1, request.Item2, ct), concurrency: 8, cancellationToken: ct).ConfigureAwait(false);
            var aRecords = records[0];
            var aaaaRecords = records[1];
            var mxRecords = records[2];
            var nsRecords = records[3];
            var soaRecords = records[4];
            var dsRecords = records[5];
            var txtApex = records[6];
            var txtDmarc = records[7];
            var txtMtasts = records[8];
            var txtTlsRpt = records[9];

            DnsSecSigned = dsRecords.Length > 0;

            ATtls = aRecords.Select(r => r.TTL).ToArray();
            AaaaTtls = aaaaRecords.Select(r => r.TTL).ToArray();
            MxTtls = mxRecords.Select(r => r.TTL).ToArray();
            NsTtls = nsRecords.Select(r => r.TTL).ToArray();
            SoaTtl = soaRecords.Length > 0 ? soaRecords[0].TTL : 0;

            // TXT TTLs
            SpfTxtTtls = txtApex
                .Where(r => (r.Data ?? string.Empty).IndexOf("v=spf1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();
            // Only treat TXT at _dmarc as DMARC when it actually contains a DMARC record
            DmarcTxtTtls = txtDmarc
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=DMARC1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

            MtastsTxtTtls = txtMtasts
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=STSv1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

            TlsRptTxtTtls = txtTlsRpt
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

            if (DkimSelectors != null && DkimSelectors.Count > 0)
            {
                var selectorRecords = await Helpers.AuthoritativeDnsProbes.RunAsync(DkimSelectors.Distinct(StringComparer.OrdinalIgnoreCase),
                    async sel => (Selector: sel, Records: await QueryDns($"{sel}._domainkey.{domainName}", DnsRecordType.TXT, ct)),
                    concurrency: 8, cancellationToken: ct).ConfigureAwait(false);
                foreach (var selectorRecord in selectorRecords) {
                    var sel = selectorRecord.Selector;
                    var name = $"{sel}._domainkey.{domainName}";
                    var dkimTxt = selectorRecord.Records;
                    var list = dkimTxt.Select(r => r.TTL).ToArray();
                    DkimTxtTtls[name] = list;
                }
            }

            await UseAuthoritativeTtlsAsync(domainName, nsRecords, logger, ct).ConfigureAwait(false);
            foreach (var dkim in DkimTxtTtls) {
                var selector = dkim.Key.Substring(0, dkim.Key.IndexOf("._domainkey.", StringComparison.OrdinalIgnoreCase));
                Evaluate($"DKIM TXT ({selector})", dkim.Value, MinTtlDkimSelectorSeconds, 86400, DnsSecSigned, logger);
            }
            Evaluate("A", ATtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("AAAA", AaaaTtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("MX", MxTtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("NS", NsTtls, 300, 86400, DnsSecSigned, logger);
            if (soaRecords.Length > 0) {
                Evaluate("SOA", new[] { SoaTtl }, 300, 86400, DnsSecSigned, logger);
            }

            // Evaluate TXT categories with specific minima
            if (SpfTxtTtls.Any()) Evaluate("SPF TXT", SpfTxtTtls, MinTtlSpfSeconds, 86400, false, logger);
            if (DmarcTxtTtls.Any()) Evaluate("DMARC TXT", DmarcTxtTtls, MinTtlDmarcSeconds, 86400, false, logger);
            if (MtastsTxtTtls.Any()) Evaluate("MTA-STS TXT", MtastsTxtTtls, MinTtlMtastsSeconds, 86400, false, logger);
            if (TlsRptTxtTtls.Any()) Evaluate("TLS-RPT TXT", TlsRptTxtTtls, MinTtlTlsRptSeconds, 86400, false, logger);
        }

	        /// <summary>
	        /// Compares TTLs across authoritative name servers for core RRsets (A, AAAA, NS, CNAME).
	        /// </summary>
	        public async Task AnalyzeUniformityAcrossServers(string domainName, InternalLogger logger, System.Threading.CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            try {
                await AnalyzeUniformityCoreAsync(domainName, logger, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                throw new OperationCanceledException(ct);
            }
        }

        private async Task AnalyzeUniformityCoreAsync(string domainName, InternalLogger logger, System.Threading.CancellationToken ct) {
            using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "TTL", target: domainName);
            UniformityIncomplete = false;
	            ServerTtlA = new(); ServerTtlAaaa = new(); ServerTtlNs = new(); ServerTtlCname = new();
	            ServerTtlTxtSpf = new(); ServerTtlTxtDmarc = new(); ServerTtlTxtMtasts = new(); ServerTtlTxtTlsRpt = new(); ServerTtlTxtPerName = new();
	            AUniformAcrossServers = AaaaUniformAcrossServers = NsUniformAcrossServers = CnameUniformAcrossServers = true;

	            var timeoutMs = UniformityQueryTimeoutMs > 0 ? UniformityQueryTimeoutMs : 4000;
	            var maxParallelism = UniformityMaxParallelism > 0 ? UniformityMaxParallelism : 1;
	            using var semaphore = new System.Threading.SemaphoreSlim(maxParallelism, maxParallelism);

            // Discover authoritative NS hosts and IPs via resolver
            var nsAnswers = await QueryDns(domainName, DnsRecordType.NS, ct);
            var nsHosts = nsAnswers.Select(a => a.Data?.Trim('.') ?? string.Empty).Where(h => !string.IsNullOrEmpty(h)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var nsIps = new HashSet<System.Net.IPAddress>();
            var addresses = await Helpers.AuthoritativeDnsProbes.RunAsync(nsHosts, async host => {
                var a = QueryDns(host, DnsRecordType.A, ct);
                var aaaa = QueryDns(host, DnsRecordType.AAAA, ct);
                await Task.WhenAll(a, aaaa).ConfigureAwait(false);
                return (await a).Concat(await aaaa);
            }, concurrency: 8, cancellationToken: ct).ConfigureAwait(false);
            foreach (var hostAddresses in addresses) {
                foreach (var ans in hostAddresses) {
                    if (System.Net.IPAddress.TryParse(ans.Data, out var ip)) {
                        nsIps.Add(ip);
                    }
                }
            }
            if (nsIps.Count == 0) {
                UniformityIncomplete = true;
                AUniformAcrossServers = AaaaUniformAcrossServers = NsUniformAcrossServers = CnameUniformAcrossServers = false;
                logger?.WriteInformationCode("TTL.Uniformity.Incomplete", "TTL uniformity could not be verified; no authoritative addresses were discovered.");
                return;
            }

            // Each responsive address can start its matrix while another address is still
            // probing reachability. Every network operation shares the same admission bound.
            var reachable = new System.Collections.Concurrent.ConcurrentDictionary<System.Net.IPAddress, byte>();
            var unavailableLabels = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
            async Task<DnsResponse?> ProbeServer(System.Net.IPAddress server) {
                await semaphore.WaitAsync(ct).ConfigureAwait(false);
                try {
                    return await _queryAuthoritative(server, domainName, DnsRecordType.NS, timeoutMs, ct, true).ConfigureAwait(false);
                } catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) { return null; }
                finally { semaphore.Release(); }
            }
            async Task<int?> SafeQuery(System.Net.IPAddress server, string name, ushort qtype, string label, DnsResponse? preflight = null) {
                if (!reachable.ContainsKey(server)) { unavailableLabels.TryAdd(label, 0); return null; }
                // Only a completed authoritative answer fulfills the NS matrix query.
                // Reachable refusals/referrals still need the ordinary record query.
                if (Helpers.AuthoritativeDnsProbes.IsAuthoritativeResponse(preflight)) {
                    var observed = ReadAuthoritativeTtl(preflight, (DnsRecordType)qtype);
                    if (!observed.Succeeded) { unavailableLabels.TryAdd(label, 0); }
                    return observed.Ttl;
                }
                await semaphore.WaitAsync(ct);
                try {
                    var response = await QueryTtlFromServer(server, name, qtype, ct, timeoutMs);
                    if (!response.Succeeded) { unavailableLabels.TryAdd(label, 0); }
                    return response.Ttl;
                } catch (System.OperationCanceledException) when (ct.IsCancellationRequested) { throw; } catch (Exception ex) {
                    logger?.WriteDebug("TTL uniformity query failed: server={0} label={1} name={2} qtype={3} error={4}", server, label, name, qtype, ex.Message);
                    unavailableLabels.TryAdd(label, 0);
                    return null;
                } finally {
                    semaphore.Release();
                }
            }

            var dkimSelectors = (DkimSelectors != null && DkimSelectors.Count > 0)
                ? DkimSelectors.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
                : Array.Empty<string>();

            var ipTasks = nsIps.Select(async ip => {
                ct.ThrowIfCancellationRequested();
                var key = ip.ToString();
                var preflight = await ProbeServer(ip).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                if (preflight != null && Helpers.AuthoritativeDnsProbes.IsUsableResponse(preflight, acceptRefused: true)) {
                    reachable.TryAdd(ip, 0);
                }

                var aTask = SafeQuery(ip, domainName, 1, "A");
                var aaaaTask = SafeQuery(ip, domainName, 28, "AAAA");
	                var nsTask = SafeQuery(ip, domainName, 2, "NS", preflight);
	                var cnameTask = SafeQuery(ip, domainName, 5, "CNAME");
	                var txtSpfTask = SafeQuery(ip, domainName, 16, "SPF TXT");
	                var txtDmarcTask = SafeQuery(ip, $"_dmarc.{domainName}", 16, "DMARC TXT");
	                var txtMtastsTask = SafeQuery(ip, $"_mta-sts.{domainName}", 16, "MTA-STS TXT");
	                var txtTlsRptTask = SafeQuery(ip, $"_smtp._tls.{domainName}", 16, "TLS-RPT TXT");

	                var dkim = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
	                var dkimTasks = dkimSelectors.Select(async sel => {
                        var name = $"{sel}._domainkey.{domainName}";
                        var ttl = await SafeQuery(ip, name, 16, $"DKIM TXT ({name})");
                        return (Name: name, Ttl: ttl);
                    }).ToArray();
	                await Task.WhenAll(new Task[] { aTask, aaaaTask, nsTask, cnameTask, txtSpfTask, txtDmarcTask, txtMtastsTask, txtTlsRptTask }
                        .Concat(dkimTasks)).ConfigureAwait(false);
	                if (dkimSelectors.Length > 0) {
	                    var dkimResults = await Task.WhenAll(dkimTasks);
	                    foreach (var dkimResult in dkimResults) {
	                        dkim[dkimResult.Name] = dkimResult.Ttl;
	                    }
	                }

	                return (Key: key, A: aTask.Result, Aaaa: aaaaTask.Result, Ns: nsTask.Result, Cname: cnameTask.Result, TxtSpf: txtSpfTask.Result, TxtDmarc: txtDmarcTask.Result, TxtMtasts: txtMtastsTask.Result, TxtTlsRpt: txtTlsRptTask.Result, Dkim: dkim);
	            }).ToArray();

	            var results = await Task.WhenAll(ipTasks);
            DomainDetective.Helpers.AuthoritativeDnsProbes.ReportIpv6Reachability(nsIps.Select(ip => ip.ToString()), reachable.Keys.Select(ip => ip.ToString()), logger);
            UniformityIncomplete = !unavailableLabels.IsEmpty;

	            foreach (var r in results) {
	                ServerTtlA[r.Key] = r.A;
	                ServerTtlAaaa[r.Key] = r.Aaaa;
	                ServerTtlNs[r.Key] = r.Ns;
	                ServerTtlCname[r.Key] = r.Cname;
	                ServerTtlTxtSpf[r.Key] = r.TxtSpf;
	                ServerTtlTxtDmarc[r.Key] = r.TxtDmarc;
	                ServerTtlTxtMtasts[r.Key] = r.TxtMtasts;
	                ServerTtlTxtTlsRpt[r.Key] = r.TxtTlsRpt;

	                foreach (var kv in r.Dkim) {
	                    if (!ServerTtlTxtPerName.TryGetValue(kv.Key, out var map)) {
	                        map = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
                        ServerTtlTxtPerName[kv.Key] = map;
                    }
                    map[r.Key] = kv.Value;
                }
            }

            EvaluateUniformity(unavailableLabels.Keys, logger);
        }

        internal void EvaluateUniformity(IEnumerable<string> failedLabels, InternalLogger logger) {
            var unavailableLabels = new HashSet<string>(failedLabels, StringComparer.Ordinal);
            UniformityIncomplete = unavailableLabels.Count > 0;
            static bool IsUniform(Dictionary<string, int?> map) =>
                map.Count > 0 && map.Values.All(value => value.HasValue) && map.Values.Distinct().Count() <= 1;
            AUniformAcrossServers = IsUniform(ServerTtlA);
            AaaaUniformAcrossServers = IsUniform(ServerTtlAaaa);
            NsUniformAcrossServers = IsUniform(ServerTtlNs);
            CnameUniformAcrossServers = IsUniform(ServerTtlCname);

            void ReportUniformity(string label, Dictionary<string, int?> map, string uniformCode, string differentCode) {
                var observed = map.Values.Where(value => value.HasValue).Distinct().ToArray();
                if (observed.Length > 1) {
                    logger?.WriteWarningCode(differentCode, "{0} TTL differs across authoritative name servers.", label);
                }
                if (unavailableLabels.Contains(label)) {
                    logger?.WriteInformationCode("TTL.Uniformity.Incomplete", "{0} TTL uniformity could not be fully verified; authoritative TTL evidence is missing.", label);
                } else if (observed.Length == 0) {
                    logger?.WriteInformationCode("TTL.Uniformity.NoRecord", "Authoritative replies contain no {0} TTL to compare.", label);
                } else if (observed.Length == 1 && map.Values.Any(value => !value.HasValue)) {
                    logger?.WriteWarningCode(differentCode, "Authoritative name servers disagree on {0} record presence.", label);
                } else if (observed.Length <= 1) {
                    logger?.WriteInformationCode(uniformCode, "{0} TTL consistent across authoritative name servers.", label);
                }
            }
            ReportUniformity("A", ServerTtlA, TtlCodes.UniformAcrossNS_A, TtlCodes.NonUniformAcrossNS_A);
            ReportUniformity("AAAA", ServerTtlAaaa, TtlCodes.UniformAcrossNS_AAAA, TtlCodes.NonUniformAcrossNS_AAAA);
            ReportUniformity("NS", ServerTtlNs, TtlCodes.UniformAcrossNS_NS, TtlCodes.NonUniformAcrossNS_NS);
            ReportUniformity("CNAME", ServerTtlCname, TtlCodes.UniformAcrossNS_CNAME, TtlCodes.NonUniformAcrossNS_CNAME);
            ReportUniformity("SPF TXT", ServerTtlTxtSpf, TtlCodes.UniformAcrossNS_TXT_SPF, TtlCodes.NonUniformAcrossNS_TXT_SPF);
            ReportUniformity("DMARC TXT", ServerTtlTxtDmarc, TtlCodes.UniformAcrossNS_TXT_DMARC, TtlCodes.NonUniformAcrossNS_TXT_DMARC);
            ReportUniformity("MTA-STS TXT", ServerTtlTxtMtasts, TtlCodes.UniformAcrossNS_TXT_MTASTS, TtlCodes.NonUniformAcrossNS_TXT_MTASTS);
            ReportUniformity("TLS-RPT TXT", ServerTtlTxtTlsRpt, TtlCodes.UniformAcrossNS_TXT_TLSRPT, TtlCodes.NonUniformAcrossNS_TXT_TLSRPT);
            foreach (var item in ServerTtlTxtPerName) {
                ReportUniformity($"DKIM TXT ({item.Key})", item.Value, TtlCodes.UniformAcrossNS_TXT_DKIM, TtlCodes.NonUniformAcrossNS_TXT_DKIM);
            }
        }
        private void Evaluate(string recordType, IEnumerable<int> ttls, int min, int max, bool dnssecSigned, InternalLogger logger) {
            var list = ttls?.ToArray() ?? Array.Empty<int>();
            var allGood = true;
            foreach (var ttl in list) {
                if (!_authoritativeTtlLabels.Contains(recordType)) {
                    if (ttl > max) {
                        var message = $"{recordType} TTL {ttl} exceeds recommended {max} seconds.";
                        _warnings.Add(message);
                        logger?.WriteWarningCode(TtlCodes.TooLong, message);
                    }
                    continue;
                }
                if (dnssecSigned && ttl >= min && ttl < 3600) {
                    var msg = $"{recordType} TTL {ttl} is shorter than recommended 3600 seconds for DNSSEC-signed zones.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooShortForDnssec, msg);
                    allGood = false;
                }
                if (ttl < min) {
                    var msg = $"{recordType} TTL {ttl} is shorter than recommended {min} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooShort, msg);
                    allGood = false;
                } else if (ttl > max) {
                    var msg = $"{recordType} TTL {ttl} exceeds recommended {max} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooLong, msg);
                    allGood = false;
                }
            }

            if (list.Any() && allGood && _authoritativeTtlLabels.Contains(recordType)) {
                logger?.WriteInformationCode(TtlCodes.Optimal, $"{recordType} TTLs within recommended range.");
            }

            if ((recordType == "A" || recordType == "AAAA") && _authoritativeTtlLabels.Contains("A")
                && _authoritativeTtlLabels.Contains("AAAA") && ATtls.Any() && AaaaTtls.Any()) {
                var avgA = ATtls.Average();
                var avgAaaa = AaaaTtls.Average();
                var ratio = Math.Max(avgA, avgAaaa) / Math.Min(avgA, avgAaaa);
                if (ratio >= 2 && !_warnings.Any(w => w.StartsWith("A and AAAA TTLs differ", StringComparison.Ordinal))) {
                    var msg = $"A and AAAA TTLs differ significantly: A {avgA} vs AAAA {avgAaaa} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.A_AAAA_Mismatch, msg);
                } else if (ratio < 2) {
                    logger?.WriteInformationCode(TtlCodes.A_AAAA_Aligned, "A and AAAA TTLs are aligned.");
                }
            }
        }
    }
}
