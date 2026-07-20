using DnsClientX;
using DomainDetective.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.IO;
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
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>When true, DnsClientX performs local DNSSEC validation.</summary>
        public bool UseLocalDnssecValidation { get; set; } = true;
        /// <summary>Optional full-response DNS override used by browser-safe callers.</summary>
        public Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? QueryDnsResponseOverride { private get; set; }
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

        /// <summary>Gets the closest enclosing signed zone whose DNSKEY RRset was evaluated.</summary>
        public string? ValidatedZone { get; private set; }

        /// <summary>Gets a value indicating whether a response for the requested subject carried authenticated-data evidence.</summary>
        public bool SubjectAuthenticData { get; private set; }

        /// <summary>Describes the evidence used for the DNSSEC result.</summary>
        public string ValidationMethod { get; private set; } = string.Empty;

        /// <summary>Gets the evidence-backed DNSSEC state for the requested subject.</summary>
        public DnssecValidationStatus ValidationStatus { get; private set; }

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
        /// <summary>Represents the recommendations value.</summary>
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
        public Task Analyze(string domainName, InternalLogger? logger, DnsConfiguration? dnsConfiguration = null, CancellationToken ct = default) {
            return AnalyzeRecord(domainName, DnsRecordType.SOA, logger, dnsConfiguration, ct);
        }

        /// <summary>Validates DNSSEC evidence for the requested subject RRset.</summary>
        internal async Task AnalyzeRecord(string domainName, DnsRecordType subjectRecordType, InternalLogger? logger, DnsConfiguration? dnsConfiguration = null, CancellationToken ct = default) {
            var effectiveLogger = logger ?? new InternalLogger();
            using var _collector = AssessmentCollector.ForAnalysis(effectiveLogger, this, category: "DNSSEC", target: domainName);
            Subject = domainName;
            Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride =
                QueryDnsResponseOverride ?? dnsConfiguration?.QueryDnsResponseOverride;
            DnsEndpoint[] endpoints = dnsConfiguration?.DnsEndpoints.Count > 0
                ? dnsConfiguration.DnsEndpoints.Distinct().ToArray()
                : new[] { dnsConfiguration?.DnsEndpoint ?? DnsEndpoint.System };
            using DnsMultiResolver? validationResolver = responseOverride == null
                ? CreateResolver(endpoints, validateDnsSec: UseLocalDnssecValidation)
                : null;
            using DnsMultiResolver? metadataResolver = responseOverride == null
                ? CreateResolver(endpoints, validateDnsSec: false)
                : null;

            ResetValidationState();
            DnsResponse subjectResponse = await Resolve(
                validationResolver, domainName, subjectRecordType, responseOverride, ct).ConfigureAwait(false);

            SubjectAuthenticData = subjectResponse.AuthenticData;
            AuthenticData = subjectResponse.AuthenticData;
            ValidationMethod = subjectResponse.DnsSecValidationAttempted
                ? "DnsClientXLocalValidation"
                : "DnsClientXValidationNotAvailable";
            ValidationStatus = MapValidationStatus(subjectResponse.DnsSecValidationStatus);
            ChainValid = subjectResponse.DnsSecValidationStatus == DnsSecValidationStatus.Secure;
            DsMatch = ChainValid;

            string validationMessage = string.IsNullOrWhiteSpace(subjectResponse.DnsSecValidationMessage)
                ? subjectResponse.Error ?? "DnsClientX did not return a local DNSSEC validation result."
                : subjectResponse.DnsSecValidationMessage;
            if (!ChainValid) {
                _mismatchSummary.Add(validationMessage);
                string code = ValidationStatus == DnssecValidationStatus.Bogus
                    ? DnssecCodes.DsMismatch
                    : DnssecCodes.DnskeyNotAuthenticated;
                effectiveLogger.WriteWarningCode(code, "DNSSEC {0} for {1}: {2}",
                    ValidationStatus, domainName, validationMessage);
            }

            var current = domainName.TrimEnd('.');
            DnsResponse? dnskeyResponse = null;
            while (!string.IsNullOrWhiteSpace(current)) {
                DnsResponse candidateResponse = await Resolve(
                    metadataResolver, current, DnsRecordType.DNSKEY, responseOverride, ct).ConfigureAwait(false);
                List<string> candidateKeys = Values(candidateResponse, DnsRecordType.DNSKEY);
                if (candidateKeys.Count > 0) {
                    ValidatedZone = current;
                    dnskeyResponse = candidateResponse;
                    DnsKeys = candidateKeys;
                    break;
                }

                int separator = current.IndexOf('.');
                if (separator < 0 || separator == current.Length - 1) break;
                current = current.Substring(separator + 1);
            }

            if (dnskeyResponse != null && !string.IsNullOrWhiteSpace(ValidatedZone)) {
                Signatures = Values(dnskeyResponse, DnsRecordType.RRSIG);
                Rrsigs = Signatures.Select(ParseRrsig).ToList();
                CheckSignatureExpirations(ValidatedZone!, effectiveLogger);

                (List<string> records, int ttl, bool ad) ds = await FetchDsRecordsWithFallback(
                    ValidatedZone!, metadataResolver, responseOverride, ct).ConfigureAwait(false);
                DsRecords = ds.records;
                DsTtls = ds.ttl > 0 ? new[] { ds.ttl } : Array.Empty<int>();
                DsAuthenticData = ds.ad;
                InspectDsMetadata(ValidatedZone!, effectiveLogger);
            }

            RootKeyTag = DnsSecTrustAnchors.Current.Count == 0
                ? 0
                : DnsSecTrustAnchors.Current[DnsSecTrustAnchors.Current.Count - 1].KeyTag;
            effectiveLogger.WriteVerbose("DNSSEC validation for {0}: {1}, chain valid: {2}",
                domainName, ValidationStatus, ChainValid);

            // Check NSEC3/NSEC3PARAM for Opt-Out usage (risk advisory)
            try {
                bool hasOptOut = await HasNsec3OptOutAsync(
                    domainName, metadataResolver, responseOverride, ct).ConfigureAwait(false);
                if (hasOptOut) {
                    effectiveLogger.WriteWarningCode(DnssecCodes.Nsec3OptOutRisk, "Zone uses NSEC3 Opt-Out");
                }
            } catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) {
                effectiveLogger.WriteDebug("NSEC3 Opt-Out check skipped: {0}", ex.Message);
            }

            if (ChainValid) {
                effectiveLogger.WriteInformationCode(DnssecCodes.SignaturesValid,
                    "DnsClientX locally verified the subject RRset signatures");
                effectiveLogger.WriteInformationCode(DnssecCodes.ChainValid,
                    "DnsClientX locally authenticated the DNSSEC chain to a bundled IANA root trust anchor");
            }

            // Positive posture: DS present at parent for the subject
            try {
                if (DsRecords != null && DsRecords.Count > 0)
                {
                    effectiveLogger.WriteInformationCode(DnssecCodes.DsPresent, "DS record present at parent");
                }
            } catch (Exception ex) when (IsNonFatalDnssecProbeException(ex, ct)) { /* non-fatal */ }

        }

        private void ResetValidationState() {
            _mismatchSummary.Clear();
            _warnings.Clear();
            KeyExpiresSoon = false;
            RootAnchorExpiration = null;
            ChainValid = false;
            DsMatch = false;
            AuthenticData = false;
            DsAuthenticData = false;
            SubjectAuthenticData = false;
            ValidatedZone = null;
            ValidationMethod = "DnsClientXLocalValidation";
            ValidationStatus = DnssecValidationStatus.NotChecked;
            DnsKeys = Array.Empty<string>();
            Signatures = Array.Empty<string>();
            Rrsigs = Array.Empty<RrsigInfo>();
            DsRecords = Array.Empty<string>();
            DsTtls = Array.Empty<int>();
            RootKeyTag = 0;
        }

        internal static DnssecValidationStatus MapValidationStatus(DnsSecValidationStatus status) => status switch {
            DnsSecValidationStatus.Secure => DnssecValidationStatus.Secure,
            DnsSecValidationStatus.Insecure => DnssecValidationStatus.Insecure,
            DnsSecValidationStatus.Bogus => DnssecValidationStatus.Bogus,
            DnsSecValidationStatus.Indeterminate => DnssecValidationStatus.Indeterminate,
            _ => DnssecValidationStatus.NotChecked
        };

        private static List<string> Values(DnsResponse response, DnsRecordType type) {
            return (response.Answers ?? Array.Empty<DnsAnswer>())
                .Where(answer => answer.Type == type)
                .Select(answer => answer.Data ?? answer.DataRaw)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToList();
        }

        private void CheckSignatureExpirations(string zone, InternalLogger logger) {
            foreach (RrsigInfo signature in Rrsigs) {
                if (signature.Expiration == DateTimeOffset.MinValue ||
                    signature.Expiration - DateTimeOffset.UtcNow > KeyExpirationWarningThreshold) continue;
                double days = (signature.Expiration - DateTimeOffset.UtcNow).TotalDays;
                string message = string.Format(CultureInfo.InvariantCulture,
                    "RRSIG for {0} expires in {1:F0} days", zone, Math.Ceiling(days));
                logger.WriteWarningCode(DnssecCodes.RrsigExpiring, message);
                _warnings.Add(message);
                KeyExpiresSoon = true;
            }
        }

        private void InspectDsMetadata(string zone, InternalLogger logger) {
            foreach (string record in DsRecords) {
                if (!IsDsDigestLengthValid(record)) {
                    logger.WriteWarningCode(DnssecCodes.DsDigestLengthUnexpected,
                        "DS record for {0} has an unsupported digest type or unexpected digest length", zone);
                }
                string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                int algorithm = AlgorithmNumber(parts[1]);
                if (!DNSKeyAnalysis.IsValidAlgorithmNumber(algorithm)) {
                    logger.WriteWarningCode(DnssecCodes.DsAlgorithmUnknown,
                        "DS record for {0} contains unknown algorithm {1}", zone, parts[1]);
                } else if (DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(algorithm)) {
                    logger.WriteWarningCode(DnssecCodes.DsAlgorithmDeprecated,
                        "DS record for {0} uses deprecated algorithm {1}", zone, parts[1]);
                }
            }
        }

        private static async Task<bool> HasNsec3OptOutAsync(string domain, DnsMultiResolver? resolver,
            Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride,
            CancellationToken ct) {
            foreach (DnsRecordType type in new[] { (DnsRecordType)51, (DnsRecordType)50 }) {
                DnsResponse response = await Resolve(
                    resolver, domain, type, responseOverride, ct).ConfigureAwait(false);
                foreach (string data in Values(response, type)) {
                    string[] parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && int.TryParse(parts[1], out int flags) && (flags & 0x01) != 0) {
                        return true;
                    }
                }
            }
            return false;
        }

        private static async Task<(List<string> records, int ttl, bool ad)> FetchDsRecordsWithFallback(string domain, DnsMultiResolver? resolver, Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride, CancellationToken ct)
        {
            var resp = await Resolve(resolver, domain, DnsRecordType.DS, responseOverride, ct).ConfigureAwait(false);
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

        private static DnsMultiResolver CreateResolver(DnsEndpoint[] endpoints, bool validateDnsSec)
        {
            DnsResolverEndpoint[] resolverEndpoints = DnsResolverEndpointFactory.From(endpoints);
            return new DnsMultiResolver(resolverEndpoints, new MultiResolverOptions {
                Strategy = MultiResolverStrategy.SequentialFallback,
                MaxParallelism = 1,
                DefaultTimeout = TimeSpan.FromSeconds(5),
                RequestDnsSec = true,
                ValidateDnsSec = validateDnsSec,
                TypedRecords = true
            });
        }

        private static async Task<DnsResponse> Resolve(DnsMultiResolver? resolver, string name,
            DnsRecordType type,
            Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride,
            CancellationToken ct) {
            if (responseOverride != null) {
                return await responseOverride(name, type, ct).ConfigureAwait(false);
            }

            if (resolver == null) {
                throw new InvalidOperationException("A DNS resolver is required when no response override is configured.");
            }

            return await resolver.QueryAsync(name, type, ct).ConfigureAwait(false);
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

            return expected >= 0 && parts[3].Length == expected && DNSKeyAnalysis.IsHexadecimal(parts[3]);
        }

        /// <summary>
        /// Computes the DNSSEC key tag from a DNSKEY record through DnsClientX.
        /// </summary>
        /// <param name="dnskeyRecord">Full DNSKEY record string.</param>
        /// <returns>Key tag value or 0 if parsing fails.</returns>
        public static int ComputeKeyTag(string dnskeyRecord) {
            return DnsSecValidator.ComputeKeyTag(dnskeyRecord);
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
