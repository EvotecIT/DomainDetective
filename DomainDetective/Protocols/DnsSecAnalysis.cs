using DnsClientX;
using DomainDetective.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml;

namespace DomainDetective {
    /// <summary>
    /// Provides DNSSEC validation utilities for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Using dnsclientx the full DNSSEC chain is retrieved and validated
    /// against DS records from the parent zone.
    /// </remarks>
    public partial class DnsSecAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        /// <summary>When true, DnsClientX performs local DNSSEC validation.</summary>
        public bool UseLocalDnssecValidation { get; set; }
        /// <summary>Optional full-response DNS override used by browser-safe callers.</summary>
        public Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? QueryDnsResponseOverride { private get; set; }
        /// <summary>
        /// Optional override for multi-resolver AD probing used in tests.
        /// Returns (ok: response success, ad: AD bit set for DS and DNSKEY).
        /// </summary>
        internal Func<DnsClientX.DnsEndpoint, string, System.Threading.CancellationToken, Task<(bool ok, bool ad)>>? AdProbeOverride { get; set; }
        private readonly List<string> _mismatchSummary = new();
        private readonly List<string> _warnings = new();

        /// <summary>
        /// Gets a list describing mismatches encountered while validating the
        /// DNSSEC chain.
        /// </summary>
        public IReadOnlyList<string> MismatchSummary => _mismatchSummary;
        /// <summary>Collection of warning messages.</summary>
        public IReadOnlyList<string> Warnings => _warnings;
        /// <summary>Gets the DS records returned for the domain.</summary>
        public IReadOnlyList<string> DsRecords { get; private set; } = new List<string>();

        /// <summary>Gets the DNSKEY records returned for the domain.</summary>
        public IReadOnlyList<string> DnsKeys { get; private set; } = new List<string>();

        /// <summary>Gets the DNSSEC signatures returned for the domain.</summary>
        public IReadOnlyList<string> Signatures { get; private set; } = new List<string>();

        /// <summary>Structured RRSIG records returned for the domain.</summary>
        public IReadOnlyList<RrsigInfo> Rrsigs { get; private set; } = new List<RrsigInfo>();

        /// <summary>Gets a value indicating whether the DNSKEY query returned authentic data.</summary>
        public bool AuthenticData { get; private set; }

        /// <summary>Gets a value indicating whether the DS query returned authentic data.</summary>
        public bool DsAuthenticData { get; private set; }

        /// <summary>Gets a value indicating whether the DS record matches the DNSKEY.</summary>
        public bool DsMatch { get; private set; }

        /// <summary>Gets a value indicating whether the full DNSSEC chain is valid.</summary>
        public bool ChainValid { get; private set; }

        /// <summary>Gets the TTL values for each parent DS record.</summary>
        public IReadOnlyList<int> DsTtls { get; private set; } = new List<int>();

        /// <summary>Gets the key tag of the root trust anchor.</summary>
        public int RootKeyTag { get; private set; }

        /// <summary>Threshold for raising key expiration warnings.</summary>
        public TimeSpan KeyExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(30);

        /// <summary>Indicates whether any key expires soon.</summary>
        public bool KeyExpiresSoon { get; private set; }

        /// <summary>Expiration date for the root trust anchor.</summary>
        public DateTimeOffset? RootAnchorExpiration { get; private set; }

        /// <summary>Structured assessments captured during DNSSEC validation.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private static readonly HttpClient _client;

        static DnsSecAnalysis()
        {
            _client = Helpers.HttpClientPlatformFactory.CreateRedirectClient();
            // _client is used for non-DNS HTTP fetches (e.g., trust anchors)
        }

        /// <summary>
        /// Performs DNSSEC validation for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to validate.</param>
        /// <param name="logger">Logger used for diagnostics.</param>
        /// <param name="dnsConfiguration">Optional DNS configuration.</param>
        /// <param name="ct">Cancellation token.</param>
        public async Task Analyze(string domainName, InternalLogger? logger, DnsConfiguration? dnsConfiguration = null, CancellationToken ct = default) {
            var effectiveLogger = logger ?? new InternalLogger();
            using var _collector = AssessmentCollector.ForAnalysis(effectiveLogger, this, category: "DNSSEC", target: domainName);
            Subject = domainName;
            var responseOverride = QueryDnsResponseOverride ?? dnsConfiguration?.QueryDnsResponseOverride;
            var hasResponseOverride = responseOverride != null;
            // Prepare a short list of fallback endpoints for robust DNSSEC queries
            var epPrimary = (dnsConfiguration?.DnsEndpoint) ?? DnsEndpoint.System;
            var endpoints = new List<DnsEndpoint> { epPrimary, DnsEndpoint.SystemTcp, DnsEndpoint.CloudflareWireFormat, DnsEndpoint.Cloudflare, DnsEndpoint.Google, DnsEndpoint.Quad9 }
                .Distinct()
                .ToArray();

            _mismatchSummary.Clear();
            _warnings.Clear();
            KeyExpiresSoon = false;
            RootAnchorExpiration = null;
            bool chainValid = true;
            bool first = true;
            string current = domainName;
            List<string> dnsKeys = new();
            List<string> signatures = new();
            List<string> dsRecords = new();
            List<int> dsTtls = new();
            int rootKeyTag = 0;

            while (true) {
                // Query DNSKEY with DO=1 to retrieve keys and signatures
                DnsResponse dnskeyResp = await ResolveWithFallback(endpoints, current, DnsRecordType.DNSKEY, requestDnsSec: true, validateDnsSec: UseLocalDnssecValidation, responseOverride, ct).ConfigureAwait(false);

                bool keyAd = dnskeyResp.AuthenticData;

                List<string> zoneKeys = new();
                List<string> zoneSigs = new();
                List<RrsigInfo> zoneSigInfos = new();
                foreach (var answer in dnskeyResp.Answers ?? Array.Empty<DnsAnswer>()) {
                    if (answer.Type == DnsRecordType.DNSKEY) {
                        var data = answer.Data ?? answer.DataRaw;
                        if (!string.IsNullOrWhiteSpace(data)) zoneKeys.Add(data);
                    } else if (answer.Type == DnsRecordType.RRSIG) {
                        var data = answer.Data ?? answer.DataRaw;
                        if (!string.IsNullOrWhiteSpace(data)) {
                            zoneSigs.Add(data);
                            var sig = ParseRrsig(data);
                            zoneSigInfos.Add(sig);
                            if (sig.Expiration != DateTimeOffset.MinValue &&
                                sig.Expiration - DateTimeOffset.UtcNow <= KeyExpirationWarningThreshold) {
                                double days = (sig.Expiration - DateTimeOffset.UtcNow).TotalDays;
                                string message = string.Format(CultureInfo.InvariantCulture,
                                    "RRSIG for {0} expires in {1:F0} days", current, Math.Ceiling(days));
                                effectiveLogger.WriteWarningCode(DnssecCodes.RrsigExpiring, message);
                                _warnings.Add(message);
                                KeyExpiresSoon = true;
                            }
                        }
                    }
                }

                var dsResult = await FetchDsRecordsWithFallback(current, endpoints, responseOverride, ct).ConfigureAwait(false);
                // Some system resolvers clear AD even when data validates. Probe well-known
                // public validating resolvers to augment AD signals so tests/environment
                // differences don't flip ChainValid.
                if ((!keyAd || !dsResult.ad) && !hasResponseOverride)
                {
                    try {
                        var (probeKeyAd, probeDsAd) = await ProbeAdStatusAsync(current, ct).ConfigureAwait(false);
                        if (!keyAd && probeKeyAd) keyAd = true;
                        if (!dsResult.ad && probeDsAd) dsResult = (dsResult.records, dsResult.ttl, ad: true);
                    } catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) { /* non-fatal */ }
                }
                dsTtls.Add(dsResult.ttl);

                List<string> currentDsRecords = dsResult.records ?? new List<string>();

                bool dsMatch = false;
                if (zoneKeys.Count > 0 && currentDsRecords.Count > 0) {
                    var ksk = zoneKeys.FirstOrDefault(k => k.StartsWith("257")) ?? zoneKeys[0];
                    dsMatch = VerifyDsMatch(ksk, currentDsRecords[0], current);
                }

                foreach (string rec in currentDsRecords) {
                    if (!IsDsDigestLengthValid(rec)) {
                        effectiveLogger.WriteWarningCode(DnssecCodes.DsDigestLengthUnexpected, "DS record for {0} has unexpected digest length", current);
                    }
                    var parts = rec.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) {
                        int alg = AlgorithmNumber(parts[1]);
                        if (!DNSKeyAnalysis.IsValidAlgorithmNumber(alg)) {
                            effectiveLogger.WriteWarningCode(DnssecCodes.DsAlgorithmUnknown, "DS record for {0} contains unknown algorithm {1}", current, parts[1]);
                        } else if (DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(alg)) {
                            effectiveLogger.WriteWarningCode(DnssecCodes.DsAlgorithmDeprecated, "DS record for {0} uses deprecated algorithm {1}", current, parts[1]);
                        }
                    }
                }

                if (!keyAd) {
                    var msg = $"DNSKEY for {current} not authenticated";
                    _mismatchSummary.Add(msg);
                    effectiveLogger.WriteWarningCode(DnssecCodes.DnskeyNotAuthenticated, msg);
                }
                if (currentDsRecords.Count == 0) {
                    var msg = $"No DS record for {current}";
                    _mismatchSummary.Add(msg);
                    effectiveLogger.WriteWarningCode(DnssecCodes.DsMissing, msg);
                } else {
                    if (!dsResult.ad) {
                        var msg = $"DS for {current} not authenticated";
                        _mismatchSummary.Add(msg);
                        effectiveLogger.WriteWarningCode(DnssecCodes.DsNotAuthenticated, msg);
                    }
                    if (!dsMatch) {
                        var msg = $"DS mismatch for {current}";
                        _mismatchSummary.Add(msg);
                        effectiveLogger.WriteWarningCode(DnssecCodes.DsMismatch, msg);
                    }
                }

                if (first) {
                    DnsKeys = zoneKeys;
                    Signatures = zoneSigs;
                    Rrsigs = zoneSigInfos;
                    DsRecords = currentDsRecords;
                    AuthenticData = keyAd;
                    DsAuthenticData = dsResult.ad;
                    DsMatch = dsMatch;
                }

                chainValid &= keyAd && dsResult.ad && dsMatch;

                int dot = current.IndexOf('.');
                if (dot == -1) {
                    if (currentDsRecords.Count > 0) {
                        string[] rootParts = currentDsRecords[0].Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (rootParts.Length > 0 && int.TryParse(rootParts[0], out int tag)) {
                            rootKeyTag = tag;
                        }
                    }
                    break;
                }

                current = current.Substring(dot + 1);
                first = false;
            }

            var anchorResult = await DownloadTrustAnchors(effectiveLogger, ct).ConfigureAwait(false);
            var anchors = anchorResult.anchors;
            RootAnchorExpiration = anchorResult.expiration;
            if (anchors.Count > 0 && rootKeyTag == 0) {
                string[] parts = anchors[0].Split(' ');
                if (parts.Length > 0 && int.TryParse(parts[0], out int tag)) {
                    rootKeyTag = tag;
                }
            }

            if (RootAnchorExpiration.HasValue) {
                double days = (RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays;
                if (days <= 0) {
                    string message = string.Format(
                        CultureInfo.InvariantCulture,
                        "Root trust anchor expired {0:F0} days ago",
                        Math.Ceiling(Math.Abs(days)));
                    effectiveLogger.WriteWarningCode(DnssecCodes.RootAnchorExpired, message);
                    _warnings.Add(message);
                    KeyExpiresSoon = true;
                } else if (days <= KeyExpirationWarningThreshold.TotalDays) {
                    string message = string.Format(
                        CultureInfo.InvariantCulture,
                        "Root trust anchor expires in {0:F0} days",
                        Math.Ceiling(days));
                    effectiveLogger.WriteWarningCode(DnssecCodes.RootAnchorExpiring, message);
                    _warnings.Add(message);
                    KeyExpiresSoon = true;
                }
            }

            ChainValid = chainValid;
            DsTtls = dsTtls;
            RootKeyTag = rootKeyTag;

            effectiveLogger.WriteVerbose("DNSSEC validation for {0}: {1}, chain valid: {2}", domainName, AuthenticData, ChainValid);

            // Check NSEC3/NSEC3PARAM for Opt-Out usage (risk advisory)
            try {
                bool hasOptOut;
                if (responseOverride != null) {
                    hasOptOut = await HasNsec3OptOutAsync(domainName, responseOverride, ct).ConfigureAwait(false);
                } else {
                    // Use System endpoint for feature check, but tolerate failure
                    using var featureResolver = new ClientX(endpoint: DnsEndpoint.System);
                    hasOptOut = await HasNsec3OptOutAsync(domainName, featureResolver, UseLocalDnssecValidation, ct).ConfigureAwait(false);
                }
                if (hasOptOut) {
                    effectiveLogger.WriteWarningCode(DnssecCodes.Nsec3OptOutRisk, "Zone uses NSEC3 Opt-Out");
                }
            } catch (Exception ex) {
                effectiveLogger.WriteDebug("NSEC3 Opt-Out check skipped: {0}", ex.Message);
            }

            if (ChainValid) {
                effectiveLogger.WriteInformationCode(DnssecCodes.SignaturesValid, "DNSSEC signatures validated");
                effectiveLogger.WriteInformationCode(DnssecCodes.ChainValid, "DNSSEC chain validated");
            }

            // Positive posture: DS present at parent for the subject
            try {
                if (DsRecords != null && DsRecords.Count > 0)
                {
                    effectiveLogger.WriteInformationCode(DnssecCodes.DsPresent, "DS record present at parent");
                }
            } catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) { /* non-fatal */ }

            if (!hasResponseOverride) {
                await MultiResolverAdCheck(domainName, effectiveLogger, ct).ConfigureAwait(false);
            }
        }

        // Probes DS and DNSKEY AD bits using multiple public resolvers and aggregates results.
        private static async Task<(bool keyAd, bool dsAd)> ProbeAdStatusAsync(string domain, CancellationToken ct)
        {
            bool anyKeyAd = false, anyDsAd = false;
            var endpoints = new[] { DnsEndpoint.Cloudflare, DnsEndpoint.Google, DnsEndpoint.Quad9 };
                foreach (var ep in endpoints)
                {
                    ct.ThrowIfCancellationRequested();
                    try {
                        using var c = new ClientX(endpoint: ep);
                    using var rCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    rCts.CancelAfter(TimeSpan.FromSeconds(5));
                    var ds = await c.Resolve(domain, DnsRecordType.DS, requestDnsSec: true, validateDnsSec: false, cancellationToken: rCts.Token).ConfigureAwait(false);
                    var dk = await c.Resolve(domain, DnsRecordType.DNSKEY, requestDnsSec: true, validateDnsSec: false, cancellationToken: rCts.Token).ConfigureAwait(false);
                        anyDsAd |= ds.AuthenticData;
                        anyKeyAd |= dk.AuthenticData;
                        if (anyDsAd && anyKeyAd) break;
                    } catch (OperationCanceledException) {
                        if (ct.IsCancellationRequested) {
                            throw;
                        }
                        // Timeout per resolver; try next.
                    } catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) {
                        // Best-effort: resolver may be unavailable; try next.
                    }
                }
                return (anyKeyAd, anyDsAd);
            }

        internal async Task MultiResolverAdCheck(string domainName, InternalLogger logger, CancellationToken ct)
        {
            try {
                int confirmed = 0;
                int total = 0;
                var endpoints = new[] { DnsClientX.DnsEndpoint.Cloudflare, DnsClientX.DnsEndpoint.Google, DnsClientX.DnsEndpoint.Quad9 };
                foreach (var ep in endpoints) {
                    ct.ThrowIfCancellationRequested();
                    (bool ok, bool ad) result;
                    if (AdProbeOverride != null)
                    {
                        result = await AdProbeOverride(ep, domainName, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        using var c = new DnsClientX.ClientX(endpoint: ep);
                        using var rCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        rCts.CancelAfter(TimeSpan.FromSeconds(5));
                        var ds = await c.Resolve(domainName, DnsClientX.DnsRecordType.DS, requestDnsSec: true, validateDnsSec: false, cancellationToken: rCts.Token).ConfigureAwait(false);
                        var dk = await c.Resolve(domainName, DnsClientX.DnsRecordType.DNSKEY, requestDnsSec: true, validateDnsSec: false, cancellationToken: rCts.Token).ConfigureAwait(false);
                        result = (ok: ds.Status == DnsClientX.DnsResponseCode.NoError && dk.Status == DnsClientX.DnsResponseCode.NoError,
                                  ad: ds.AuthenticData && dk.AuthenticData);
                    }
                    if (result.ok) { total++; if (result.ad) confirmed++; }
                }
                if (confirmed >= 2) {
                    logger.WriteInformationCode(DnssecCodes.AuthenticDataMultiResolver, "AD bit set for DS/DNSKEY via {0} resolvers", confirmed);
                    Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Info,
                        Category = "DNSSEC",
                        Code = DnssecCodes.AuthenticDataMultiResolver,
                        Target = domainName,
                        Message = $"AD bit confirmed by {confirmed} resolvers (DS/DNSKEY)."
                    });
                }
            } catch (Exception ex) {
                logger.WriteDebug("DNSSEC multi-resolver AD check skipped: {0}", ex.Message);
            }
        }

        private static async Task<bool> HasNsec3OptOutAsync(string domain, ClientX resolver, bool validateLocally, CancellationToken ct) {
            // Check NSEC3PARAM (51) first
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var nsec3param = await resolver.Resolve(domain, (DnsRecordType)51, requestDnsSec: true, validateDnsSec: validateLocally, cancellationToken: cts.Token).ConfigureAwait(false);
            foreach (var ans in nsec3param.Answers ?? Array.Empty<DnsAnswer>()) {
                if ((int)ans.Type == 51) {
                    var data = ans.Data ?? ans.DataRaw; // Hash Flags Iterations Salt
                    if (!string.IsNullOrWhiteSpace(data)) {
                        var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                            return true;
                        }
                    }
                }
            }
            // Fallback: inspect NSEC3 (50) flags field
            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts2.CancelAfter(TimeSpan.FromSeconds(5));
            var nsec3 = await resolver.Resolve(domain, (DnsRecordType)50, requestDnsSec: true, validateDnsSec: validateLocally, cancellationToken: cts2.Token).ConfigureAwait(false);
            foreach (var ans in nsec3.Answers ?? Array.Empty<DnsAnswer>()) {
                if ((int)ans.Type == 50) {
                    var data = ans.Data ?? ans.DataRaw; // Hash Flags Iterations Salt Next TypeBitMaps
                    if (!string.IsNullOrWhiteSpace(data)) {
                        var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private static async Task<bool> HasNsec3OptOutAsync(string domain, Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>> responseOverride, CancellationToken ct) {
            var nsec3param = await responseOverride(domain, (DnsRecordType)51, ct).ConfigureAwait(false);
            foreach (var ans in (nsec3param.Answers ?? Array.Empty<DnsAnswer>()).Where(static answer => (int)answer.Type == 51)) {
                var data = ans.Data ?? ans.DataRaw;
                if (!string.IsNullOrWhiteSpace(data)) {
                    var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                        return true;
                    }
                }
            }

            var nsec3 = await responseOverride(domain, (DnsRecordType)50, ct).ConfigureAwait(false);
            foreach (var ans in (nsec3.Answers ?? Array.Empty<DnsAnswer>()).Where(static answer => (int)answer.Type == 50)) {
                var data = ans.Data ?? ans.DataRaw;
                if (!string.IsNullOrWhiteSpace(data)) {
                    var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                        return true;
                    }
                }
            }

            return false;
        }

        private static async Task<(List<string> records, int ttl, bool ad)> FetchDsRecordsWithFallback(string domain, DnsEndpoint[] endpoints, Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride, CancellationToken ct)
        {
            var resp = await ResolveWithFallback(endpoints, domain, DnsRecordType.DS, requestDnsSec: true, validateDnsSec: false, responseOverride, ct).ConfigureAwait(false);
            bool ad = resp.AuthenticData;
            List<string> records = new();
            int ttl = 0;
            foreach (var ans in resp.Answers ?? Array.Empty<DnsAnswer>()) {
                if (ans.Type == DnsRecordType.DS) {
                    var data = ans.Data ?? ans.DataRaw;
                    if (!string.IsNullOrWhiteSpace(data)) records.Add(data);
                    if (ttl == 0) ttl = ans.TTL;
                }
            }
            return (records, ttl, ad);
        }

        private static async Task<DnsResponse> ResolveWithFallback(DnsEndpoint[] endpoints, string name, DnsRecordType type, bool requestDnsSec, bool validateDnsSec, Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride, CancellationToken ct)
        {
            if (responseOverride != null) {
                return await responseOverride(name, type, ct).ConfigureAwait(false);
            }

            foreach (var ep in endpoints)
            {
                try {
                    using var rCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    rCts.CancelAfter(TimeSpan.FromSeconds(5));
                    using var c = new ClientX(endpoint: ep);
                    var resp = await c.Resolve(name, type, requestDnsSec: requestDnsSec, validateDnsSec: validateDnsSec, cancellationToken: rCts.Token).ConfigureAwait(false);
                    if (resp != null && (resp.Answers?.Length ?? 0) > 0) return resp;
                } catch (OperationCanceledException) {
                    if (ct.IsCancellationRequested) {
                        throw;
                    }
                    // Timeout per endpoint; try next fallback.
                } catch (Exception) {
                    // Best-effort: endpoint may be unavailable; try next fallback.
                }
            }
            // Last attempt with system (may be empty)
            using (var c = new ClientX(endpoint: DnsEndpoint.System))
            {
                try { return await c.Resolve(name, type, requestDnsSec: requestDnsSec, validateDnsSec: validateDnsSec, cancellationToken: ct).ConfigureAwait(false); }
                catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) { return new DnsResponse { Answers = Array.Empty<DnsAnswer>() }; }
            }
        }

        private static bool IsNonFatalDnssecProbeException(Exception exception, CancellationToken cancellationToken) {
            if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested) {
                return false;
            }

            return exception is HttpRequestException
                || exception is IOException
                || exception is InvalidOperationException
                || exception is ObjectDisposedException
                || exception is SocketException
                || exception is TaskCanceledException;
        }

        private static bool IsDsDigestLengthValid(string record) {
            var parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4 || !int.TryParse(parts[2], out int digestType)) {
                return true;
            }

            int expected = digestType switch {
                1 => 40,
                2 => 64,
                4 => 96,
                _ => -1,
            };

            return expected < 0 || parts[3].Length == expected;
        }

        /// <summary>
        /// Validates that the provided DS record matches the specified DNSKEY.
        /// </summary>
        /// <param name="dnskey">DNSKEY record data.</param>
        /// <param name="dsRecord">DS record data.</param>
        /// <param name="domainName">Domain name used in the calculation.</param>
        /// <returns><c>true</c> if the DS record corresponds to the DNSKEY; otherwise <c>false</c>.</returns>
        private static bool VerifyDsMatch(string dnskey, string dsRecord, string domainName) {
            if (string.IsNullOrWhiteSpace(dnskey) || string.IsNullOrWhiteSpace(dsRecord)) {
            return false;
        }
            try {
                var keyParts = dnskey.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (keyParts.Length < 4) {
                    return false;
                }

                var flags = ushort.Parse(keyParts[0]);
                var protocol = byte.Parse(keyParts[1]);
                var algorithm = AlgorithmNumber(keyParts[2]);
                if (!DNSKeyAnalysis.IsValidAlgorithmNumber(algorithm)) {
                    return false;
                }
                var publicKeyBytes = Convert.FromBase64String(keyParts[3]);

                var rdata = new List<byte>();
                var flagBytes = BitConverter.GetBytes((ushort)flags);
                Array.Reverse(flagBytes);
                rdata.AddRange(flagBytes);
                rdata.Add(protocol);
                rdata.Add((byte)algorithm);
                rdata.AddRange(publicKeyBytes);

                var dsParts = dsRecord.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (dsParts.Length < 4) {
                    return false;
                }

                var keyTag = int.Parse(dsParts[0]);
                var dsAlgorithm = AlgorithmNumber(dsParts[1]);
                if (!DNSKeyAnalysis.IsValidAlgorithmNumber(dsAlgorithm)) {
                    return false;
                }
                var digestType = int.Parse(dsParts[2]);
                var digest = dsParts[3];
                if (!DNSKeyAnalysis.IsHexadecimal(digest)) {
                    return false;
                }

                int computedKeyTag = ComputeKeyTag(dnskey);
                if (computedKeyTag != keyTag || dsAlgorithm != algorithm) {
                    return false;
                }

                byte[] digestBytes;
                using HashAlgorithm hasher = digestType switch {
                    1 => SHA1.Create(),
                    2 => SHA256.Create(),
                    4 => SHA384.Create(),
                    _ => SHA256.Create(),
                };
                byte[] nameWire = ToWireFormat(domainName);
                var data = new byte[nameWire.Length + rdata.Count];
                nameWire.CopyTo(data, 0);
                rdata.ToArray().CopyTo(data, nameWire.Length);
                digestBytes = hasher.ComputeHash(data);
                var digestHex = BitConverter.ToString(digestBytes).Replace("-", string.Empty).ToLowerInvariant();

                return digestHex.StartsWith(digest.ToLowerInvariant());
            } catch (Exception) {
                // Any parsing/crypto error => treat as mismatch.
                return false;
            }
        }

        /// <summary>
        /// Computes the DNSSEC key tag for the given RDATA sequence.
        /// </summary>
        /// <param name="rdata">RDATA bytes from the DNSKEY record.</param>
        /// <returns>The computed key tag.</returns>
        private static int ComputeKeyTag(List<byte> rdata) {
            int ac = 0;
            for (int i = 0; i < rdata.Count; i++) {
                ac += (i & 1) == 1 ? rdata[i] : rdata[i] << 8;
            }
            ac += (ac >> 16) & 0xFFFF;
            return ac & 0xFFFF;
        }

        /// <summary>
        /// Computes the DNSSEC key tag from a DNSKEY record.
        /// </summary>
        /// <param name="dnskeyRecord">Full DNSKEY record string.</param>
        /// <returns>Key tag value or 0 if parsing fails.</returns>
        public static int ComputeKeyTag(string dnskeyRecord) {
            if (string.IsNullOrWhiteSpace(dnskeyRecord)) {
                return 0;
            }

            var parts = dnskeyRecord.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) {
                return 0;
            }

            if (!ushort.TryParse(parts[0], out ushort flags) ||
                !byte.TryParse(parts[1], out byte protocol)) {
                return 0;
            }

            int algorithm = AlgorithmNumber(parts[2]);
            if (!DNSKeyAnalysis.IsValidAlgorithmNumber(algorithm)) {
                return 0;
            }

            byte[] publicKeyBytes = Convert.FromBase64String(parts[3]);
            List<byte> rdata = new();
            var flagBytes = BitConverter.GetBytes(flags);
            Array.Reverse(flagBytes);
            rdata.AddRange(flagBytes);
            rdata.Add(protocol);
            rdata.Add((byte)algorithm);
            rdata.AddRange(publicKeyBytes);

            return ComputeKeyTag(rdata);
        }

        /// <summary>
        /// Converts a domain name to its DNS wire format representation.
        /// </summary>
        /// <param name="domainName">Domain name to convert.</param>
        /// <returns>Byte array containing the wire format representation.</returns>
        private static byte[] ToWireFormat(string domainName) {
            domainName = domainName.TrimEnd('.').ToLowerInvariant();
            var labels = domainName.Split('.');
            List<byte> bytes = new();
            foreach (var label in labels) {
                bytes.Add((byte)label.Length);
                bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
            }
            bytes.Add(0);
            return bytes.ToArray();
        }

        /// <summary>
        /// Maps DNS algorithm names to their numeric identifiers.
        /// </summary>
        /// <param name="name">Algorithm name.</param>
        /// <returns>Numeric algorithm identifier.</returns>
        private static int AlgorithmNumber(string name) {
            if (string.IsNullOrWhiteSpace(name)) {
                return 0;
            }

            if (int.TryParse(name, out int numeric)) {
                return DNSKeyAnalysis.IsValidAlgorithmNumber(numeric) ? numeric : 0;
            }

            return name.ToUpperInvariant() switch {
                "RSAMD5" => 1,
                "DH" => 2,
                "DSA" => 3,
                "ECC" => 4,
                "RSASHA1" => 5,
                "DSANSEC3SHA1" => 6,
                "RSASHA1NSEC3SHA1" => 7,
                "RSASHA256" => 8,
                "RSASHA512" => 10,
                "ECCGOST" => 12,
                "ECDSAP256SHA256" => 13,
                "ECDSAP384SHA384" => 14,
                "ED25519" => 15,
                "ED448" => 16,
                "INDIRECT" => 252,
                "PRIVATEDNS" => 253,
                "PRIVATEOID" => 254,
                _ => 0,
            };
        }

        private static bool VerifyEcdsaSignature(string key, string signature, byte[] data, int algorithm) {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(signature) || data == null) {
                return false;
            }

            try {
                byte[] pub = Convert.FromBase64String(key);
                byte[] sig = Convert.FromBase64String(signature);
                int fieldSize = algorithm == 14 ? 48 : 32;
                if (pub.Length != fieldSize * 2 || sig.Length != fieldSize * 2) {
                    return false;
                }

                ECParameters p = new() {
                    Curve = algorithm == 14 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint {
                        X = pub.AsSpan(0, fieldSize).ToArray(),
                        Y = pub.AsSpan(fieldSize, fieldSize).ToArray(),
                    }
                };

                using ECDsa ecdsa = ECDsa.Create(p);
                HashAlgorithmName hash = algorithm == 14 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
                return ecdsa.VerifyData(data, sig, hash);
            } catch (Exception) {
                // Treat invalid key/signature formats as verification failure.
                return false;
            }
        }

        private static byte[] P1363ToDer(byte[] signature, int size) {
            int half = signature.Length / 2;
            byte[] r = new byte[half];
            byte[] s = new byte[half];
            Array.Copy(signature, 0, r, 0, half);
            Array.Copy(signature, half, s, 0, half);

            r = TrimLeadingZeros(r);
            s = TrimLeadingZeros(s);

            if (r[0] >= 0x80) {
                r = PrependZero(r);
            }
            if (s[0] >= 0x80) {
                s = PrependZero(s);
            }

            int len = 2 + r.Length + 2 + s.Length;
            byte[] der = new byte[len + 2];
            int pos = 0;
            der[pos++] = 0x30;
            der[pos++] = (byte)len;
            der[pos++] = 0x02;
            der[pos++] = (byte)r.Length;
            Array.Copy(r, 0, der, pos, r.Length);
            pos += r.Length;
            der[pos++] = 0x02;
            der[pos++] = (byte)s.Length;
            Array.Copy(s, 0, der, pos, s.Length);
            return der;
        }

        private static byte[] TrimLeadingZeros(byte[] value) {
            int i = 0;
            while (i < value.Length - 1 && value[i] == 0) {
                i++;
            }
            if (i == 0) {
                return value;
            }

            byte[] output = new byte[value.Length - i];
            Array.Copy(value, i, output, 0, output.Length);
            return output;
        }

        private static byte[] PrependZero(byte[] value) {
            byte[] output = new byte[value.Length + 1];
            output[0] = 0;
            Array.Copy(value, 0, output, 1, value.Length);
            return output;
        }

        private static RrsigInfo ParseRrsig(string record) {
            if (string.IsNullOrWhiteSpace(record)) {
                return new RrsigInfo();
            }

            string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 7) {
                return new RrsigInfo();
            }

            DateTimeOffset inception = DateTimeOffset.MinValue;
            DateTimeOffset expiration = DateTimeOffset.MinValue;
            if (long.TryParse(parts[5], out long inc)) {
                inception = DateTimeOffset.FromUnixTimeSeconds(inc);
            } else if (DateTimeOffset.TryParseExact(parts[5], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var incDt)) {
                inception = incDt;
            }

            if (long.TryParse(parts[4], out long exp)) {
                expiration = DateTimeOffset.FromUnixTimeSeconds(exp);
            } else if (DateTimeOffset.TryParseExact(parts[4], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expDt)) {
                expiration = expDt;
            }

            _ = int.TryParse(parts[6], out int keyTag);

            string algorithm = parts[1];
            if (int.TryParse(parts[1], out int algNum)) {
                string name = DNSKeyAnalysis.AlgorithmName(algNum);
                if (!string.IsNullOrEmpty(name)) {
                    algorithm = name;
                }
            }

            return new RrsigInfo {
                Algorithm = algorithm,
                KeyTag = keyTag,
                Inception = inception,
                Expiration = expiration,
            };
        }
    }
}
