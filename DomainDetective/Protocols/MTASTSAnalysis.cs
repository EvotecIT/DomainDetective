using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Provides functionality for retrieving and analysing MTA-STS policies.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public class MTASTSAnalysis : IHasAssessments {
    private record CacheEntry(string PolicyId, string Policy, DateTimeOffset Expires);
    private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Upper limit for how long a fetched policy is cached. The actual
    /// expiration is the lesser of this value and the policy's <c>max_age</c>.
    /// </summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Removes all cached policies.</summary>
    public static void ClearCache() => _cache.Clear();
        /// <summary>
        /// Gets the domain name that was analysed.
        /// </summary>
        public string Domain { get; private set; } = string.Empty;

        /// <summary>
        /// Gets a value indicating whether the policy was successfully fetched.
        /// </summary>
        public bool PolicyPresent { get; private set; }

        /// <summary>
        /// Gets a value indicating whether only the DNS bootstrap was evaluated.
        /// </summary>
        public bool PolicyFetchSkipped { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy is valid.
        /// </summary>
        public bool PolicyValid { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy version is valid.
        /// </summary>
        public bool ValidVersion { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy contained a version field.
        /// </summary>
        public bool VersionPresent { get; private set; }

        /// <summary>
        /// Gets a value indicating whether any field appeared more than once.
        /// </summary>
        public bool HasDuplicateFields { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy mode is valid.
        /// </summary>
        public bool ValidMode { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the Max-Age value is valid.
        /// </summary>
        public bool ValidMaxAge { get; private set; }

        /// <summary>
        /// Gets a value indicating whether at least one MX entry was found.
        /// </summary>
        public bool HasMx { get; private set; }

        /// <summary>
        /// Gets the policy mode value.
        /// </summary>
        public string Mode { get; private set; } = string.Empty;

        /// <summary>
        /// Gets the Max-Age value defined by the policy.
        /// </summary>
        public int MaxAge { get; private set; }

        /// <summary>
        /// Gets the list of MX entries found in the policy.
        /// </summary>
        public List<string> Mx { get; private set; } = new List<string>();

        /// <summary>
        /// Gets the text of the policy.
        /// </summary>
        public string Policy { get; private set; } = string.Empty;

        /// <summary>
        /// Gets a value indicating whether the policy enforces MTA-STS.
        /// </summary>
        public bool EnforcesMtaSts => PolicyValid && string.Equals(Mode, "enforce", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Gets or sets the logger instance used for reporting warnings.
        /// </summary>
        internal InternalLogger Logger { get; set; } = new InternalLogger(false);

        /// <summary>
        /// Gets or sets a policy URL override. When set, this URL is used
        /// instead of constructing one from the domain name. Primarily
        /// intended for testing.
        /// </summary>
        public string? PolicyUrlOverride { get; set; }

        /// <summary>
        /// Provides DNS configuration used for queries.
        /// </summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>
        /// Optional DNS query override for testing.
        /// </summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>
        /// Gets a value indicating whether the TXT record exists.
        /// </summary>
        public bool DnsRecordPresent { get; private set; }

        /// <summary>Gets a value indicating whether multiple MTA-STS TXT resource records were returned.</summary>
        public bool MultipleDnsRecords { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the TXT record is valid.
        /// </summary>
        public bool DnsRecordValid { get; private set; }

        /// <summary>HTTP client used to retrieve policy text without following redirects.</summary>
        public HttpClient HttpClient { get; set; } = _client;
        /// <summary>Optional factory used to create a constrained outbound HTTP handler.</summary>
        public Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

        /// <summary>
        /// Gets the policy ID extracted from the TXT record.
        /// </summary>
        public string PolicyId { get; private set; } = string.Empty;

        /// <summary>DNS TTL (seconds) of the _mta-sts TXT record as returned by DNS.</summary>
        public int? DnsRecordTtl { get; private set; }
        /// <summary>TTL (seconds) of the CNAME record when this record was resolved via CNAME alias.</summary>
        public int? CnameTtl { get; private set; }
        /// <summary>True when the MTA-STS TXT record was resolved through a CNAME alias.</summary>
        public bool IsCnameResolved { get; private set; }

        /// <summary>Summary message describing MTA-STS status.</summary>
        public string Advisory { get; private set; } = string.Empty;

        /// <summary>Indicates whether policy MX patterns cover actual DNS MX hosts.</summary>
        public bool MxAligned { get; private set; }
        /// <summary>Actual MX hosts missing from the policy patterns.</summary>
        public List<string> MissingMxFromPolicy { get; private set; } = new();

        /// <summary>Relevant standards for MTA-STS analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "SMTP MTA Strict Transport Security", Reference = "RFC 8461", Url = "https://datatracker.ietf.org/doc/html/rfc8461" }
        };

        /// <summary>
        /// Resets analysis state so the instance can be reused.
        /// </summary>
        public void Reset() {
            Domain = string.Empty;
            PolicyPresent = false;
            PolicyFetchSkipped = false;
            PolicyValid = false;
            ValidVersion = false;
            VersionPresent = false;
            HasDuplicateFields = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = string.Empty;
            MaxAge = 0;
            Mx = new List<string>();
            Policy = string.Empty;
            DnsRecordPresent = false;
            MultipleDnsRecords = false;
            DnsRecordValid = false;
            PolicyId = string.Empty;
            Advisory = string.Empty;
            MxAligned = false;
            MissingMxFromPolicy = new List<string>();
            DnsRecordTtl = null;
            CnameTtl = null;
            IsCnameResolved = false;
        }

        /// <summary>
        /// Fetches and analyses the policy for the specified domain using HTTPS.
        /// </summary>
        /// <param name="domainName">The domain to query.</param>
        /// <param name="logger">A logger for warning messages.</param>
        /// <param name="cancellationToken">Token used to cancel DNS and HTTP operations.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public async Task AnalyzePolicy(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "MTASTS", target: domainName);
            Reset();
            Logger = logger;

            if (!Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out _)) {
                throw new ArgumentException("Invalid host name.", nameof(domainName));
            }
            Domain = domainName;

            var dns = await QueryDns($"_mta-sts.{domainName}", DnsRecordType.TXT, cancellationToken);
            var dnsList = dns?.ToList() ?? new List<DnsAnswer>();

            // Capture CNAME TTL before filtering
            var cnameRecords = dnsList.Where(r => r.Type == DnsRecordType.CNAME).ToList();
            if (cnameRecords.Any()) {
                IsCnameResolved = true;
                CnameTtl = cnameRecords.Min(r => r.TTL);
            }

            var allTxtRecords = dnsList.Where(r => r.Type == DnsRecordType.TXT).ToList();
            var txtRecords = allTxtRecords.Where(r =>
                r.TxtConcatenatedData.StartsWith("v=STSv1;", StringComparison.Ordinal)).ToList();
            DnsRecordTtl = DnsAnswerTtlHelper.MinPositiveTtl(allTxtRecords, expectedType: DnsRecordType.TXT);
            DnsRecordPresent = txtRecords.Any();
            MultipleDnsRecords = txtRecords.Count > 1;
            if (!DnsRecordPresent) {
                PolicyValid = false;
                UpdateAdvisory();
                return;
            }

            if (MultipleDnsRecords) {
                PolicyValid = false;
                UpdateAdvisory();
                return;
            }

            ParseDnsRecord(txtRecords[0].TxtConcatenatedData);
            if (!DnsRecordValid) {
                PolicyValid = false;
                UpdateAdvisory();
                return;
            }

            string url = PolicyUrlOverride ?? $"https://mta-sts.{domainName}/.well-known/mta-sts.txt";
            var key = PolicyUrlOverride ?? domainName;

            if (_cache.TryGetValue(key, out var entry) && entry.Expires > DateTimeOffset.UtcNow && entry.PolicyId == PolicyId) {
                PolicyPresent = true;
                Policy = entry.Policy;
                ParsePolicy(entry.Policy);
                PolicyValid = PolicyValid && DnsRecordValid;
                UpdateAdvisory();
                return;
            }

            string? content = await GetPolicy(url, cancellationToken);
            if (content == null) {
                PolicyPresent = false;
                PolicyValid = false;
                UpdateAdvisory();
                return;
            }

            Logger?.WriteInformationCode(MtaStsCodes.HttpsAvailable, "MTA-STS policy host reachable.");
            PolicyPresent = true;
            Policy = content;
            ParsePolicy(content);
            PolicyValid = PolicyValid && DnsRecordValid;
            await EvaluateMxAlignmentAsync(domainName, cancellationToken);
            var expiration = DateTimeOffset.UtcNow.Add(CacheDuration);
            if (ValidMaxAge && MaxAge > 0) {
                var maxAgeExpiration = DateTimeOffset.UtcNow.Add(TimeSpan.FromSeconds(MaxAge));
                if (maxAgeExpiration < expiration) {
                    expiration = maxAgeExpiration;
                }
            }
            var cacheEntry = new CacheEntry(PolicyId, content, expiration);
            _cache[key] = cacheEntry;
            UpdateAdvisory();
        }

        /// <summary>
        /// Analyzes only the DNS bootstrap record for the specified domain.
        /// </summary>
        /// <param name="domainName">The domain to query.</param>
        /// <param name="logger">A logger for warning messages.</param>
        /// <param name="cancellationToken">Token used to cancel the DNS operation.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public async Task AnalyzeDnsBootstrap(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "MTASTS", target: domainName);
            Reset();
            Logger = logger;

            if (!Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out _)) {
                throw new ArgumentException("Invalid host name.", nameof(domainName));
            }
            Domain = domainName;

            var dns = await QueryDns($"_mta-sts.{domainName}", DnsRecordType.TXT, cancellationToken);
            var dnsList = dns?.ToList() ?? new List<DnsAnswer>();

            var cnameRecords = dnsList.Where(r => r.Type == DnsRecordType.CNAME).ToList();
            if (cnameRecords.Any()) {
                IsCnameResolved = true;
                CnameTtl = cnameRecords.Min(r => r.TTL);
            }

            var allTxtRecords = dnsList.Where(r => r.Type == DnsRecordType.TXT).ToList();
            var txtRecords = allTxtRecords.Where(r =>
                r.TxtConcatenatedData.StartsWith("v=STSv1;", StringComparison.Ordinal)).ToList();
            DnsRecordTtl = DnsAnswerTtlHelper.MinPositiveTtl(allTxtRecords, expectedType: DnsRecordType.TXT);
            DnsRecordPresent = txtRecords.Any();
            MultipleDnsRecords = txtRecords.Count > 1;
            if (DnsRecordPresent && !MultipleDnsRecords) {
                ParseDnsRecord(txtRecords[0].TxtConcatenatedData);
            }

            PolicyFetchSkipped = true;
            UpdateBootstrapAdvisory();
        }

        /// <summary>
        /// Analyses the supplied policy text.
        /// </summary>
        /// <param name="text">Raw policy contents.</param>
        public void AnalyzePolicyText(string text) {
            Reset();
            ParsePolicy(text);
            UpdateAdvisory();
        }

        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private void UpdateAdvisory() {
            if (!DnsRecordPresent) {
                Advisory = "No MTA-STS record published.";
                Logger?.WriteWarningCode(MtaStsCodes.MissingRecord, Advisory);
            } else if (MultipleDnsRecords) {
                Advisory = "Multiple MTA-STS DNS bootstrap records published; policy discovery is invalid.";
                Logger?.WriteWarningCode(MtaStsCodes.PolicyInvalid, Advisory);
            } else if (!PolicyValid) {
                Advisory = "MTA-STS policy invalid.";
                Logger?.WriteWarningCode(MtaStsCodes.PolicyInvalid, Advisory);
            } else {
                Logger?.WriteInformationCode(MtaStsCodes.PolicyValid, "MTA-STS policy valid.");
                if (!EnforcesMtaSts) {
                    Advisory = "MTA-STS policy present but not enforcing.";
                    Logger?.WriteWarningCode(MtaStsCodes.NotEnforcing, Advisory);
                } else {
                    Advisory = "MTA-STS policy enforced.";
                    Logger?.WriteInformationCode(MtaStsCodes.Enforced, "{0}", Advisory);
                }
            }
        }

        private void UpdateBootstrapAdvisory() {
            if (!DnsRecordPresent) {
                Advisory = "No MTA-STS DNS bootstrap record published.";
                Logger?.WriteWarningCode(MtaStsCodes.MissingRecord, Advisory);
            } else if (MultipleDnsRecords) {
                Advisory = "Multiple MTA-STS DNS bootstrap records published; policy discovery is invalid.";
                Logger?.WriteWarningCode(MtaStsCodes.PolicyInvalid, Advisory);
            } else if (!DnsRecordValid) {
                Advisory = "MTA-STS DNS bootstrap record is present but invalid.";
                Logger?.WriteWarningCode(MtaStsCodes.PolicyInvalid, Advisory);
            } else {
                Advisory = "MTA-STS DNS bootstrap record is present. Policy fetch was not evaluated in this pass.";
                Logger?.WriteInformationCode(MtaStsCodes.PolicyValid, Advisory);
            }
        }

        private static readonly HttpClient _client;

        static MTASTSAnalysis()
        {
            _client = HttpClientPlatformFactory.CreateNoRedirectClient(userAgent: "Mozilla/5.0");
        }

        /// <summary>
        /// Retrieves the policy contents from the specified URL.
        /// </summary>
        /// <param name="url">The policy URL.</param>
        /// <param name="cancellationToken">Token used to cancel the HTTP request.</param>
        /// <returns>The policy text or <see langword="null"/> if the request failed.</returns>
        private async Task<string?> GetPolicy(string url, CancellationToken cancellationToken) {
            try {
                var requestedUri = new Uri(url, UriKind.Absolute);
                var client = HttpHandlerFactory == null ? HttpClient : new HttpClient(HttpHandlerFactory(), disposeHandler: true);
                using var disposableClient = HttpHandlerFactory == null ? null : client;
                using var response = await client.GetAsync(requestedUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (response.StatusCode != HttpStatusCode.OK) {
                    Logger?.WriteWarningCode(MtaStsCodes.FetchFailed, "MTA-STS policy fetch returned HTTP {0}; HTTP 200 is required.", (int)response.StatusCode);
                    return null;
                }
                if (response.RequestMessage?.RequestUri is Uri finalUri && finalUri != requestedUri) {
                    Logger?.WriteWarningCode(MtaStsCodes.FetchFailed, "MTA-STS policy retrieval followed a redirect, which RFC 8461 prohibits.");
                    return null;
                }
                cancellationToken.ThrowIfCancellationRequested();
                return await response.Content.ReadAsStringAsync();
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                Logger?.WriteWarningCode(MtaStsCodes.FetchFailed, $"Failed to fetch {url}: {ex.Message}");
            }

            return null;
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            if (QueryDnsOverride != null) {
                var result = await QueryDnsOverride(name, type);
                cancellationToken.ThrowIfCancellationRequested();
                return result;
            }

            if (type == DnsRecordType.TXT) {
                return await DnsConfiguration.QueryDNS(name, type, filter: string.Empty, includeAliasesInFilter: true, cancellationToken: cancellationToken);
            }
            return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken);
        }

        private void ParseDnsRecord(string record) {
            DnsRecordValid = false;
            PolicyId = string.Empty;
            if (string.IsNullOrWhiteSpace(record)) {
                return;
            }

            var parts = record.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            bool hasVersion = false;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in parts) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();

                if (!seen.Add(key)) {
                    HasDuplicateFields = true;
                }

                switch (key) {
                    case "v":
                        hasVersion = value == "STSv1";
                        break;
                    case "id":
                        PolicyId = value;
                        break;
                }
            }

            DnsRecordValid = hasVersion && !string.IsNullOrEmpty(PolicyId);
        }

        /// <summary>
        /// Parses the supplied policy text and updates property values.
        /// </summary>
        /// <param name="text">Raw policy text.</param>
        private void ParsePolicy(string text) {
            PolicyValid = true;
            ValidVersion = false;
            VersionPresent = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = string.Empty;
            MaxAge = 0;
            Mx = new List<string>();

            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in lines) {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("#") || trimmed.Length == 0) {
                    continue;
                }

                int colonIndex = trimmed.IndexOf(':');
                if (colonIndex <= 0) {
                    PolicyValid = false;
                    continue;
                }

                string key = trimmed.Substring(0, colonIndex).Trim();
                string value = trimmed.Substring(colonIndex + 1).Trim();
                var lowerKey = key.ToLowerInvariant();
                if (lowerKey != "mx" && !seen.Add(lowerKey)) {
                    HasDuplicateFields = true;
                }

                switch (lowerKey) {
                    case "version":
                        VersionPresent = true;
                        ValidVersion = value == "STSv1";
                        break;
                    case "mode":
                        Mode = value;
                        ValidMode = value == "enforce" || value == "testing" || value == "none";
                        break;
                    case "max_age":
                        if (int.TryParse(value, out int ma)) {
                            MaxAge = ma;
                            ValidMaxAge = ma > 0;
                        }
                        break;
                    case "mx":
                        Mx.Add(value);
                        HasMx = true;
                        break;
                    default:
                        break;
                }
            }

            PolicyValid = PolicyValid && VersionPresent && ValidVersion && ValidMode && ValidMaxAge && HasMx && !HasDuplicateFields;
        }

        private static bool PatternMatches(string pattern, string host)
        {
            if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(host)) return false;
            var p = pattern.TrimEnd('.');
            var h = host.TrimEnd('.');
            if (p.StartsWith("*.", StringComparison.Ordinal))
            {
                var suf = p.Substring(1); // ".example.com"
                return h.EndsWith(suf, StringComparison.OrdinalIgnoreCase);
            }
            return string.Equals(p, h, StringComparison.OrdinalIgnoreCase);
        }

        private async Task EvaluateMxAlignmentAsync(string domainName, CancellationToken cancellationToken)
        {
            try {
                MissingMxFromPolicy = new List<string>();
                MxAligned = false;
                var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                var hosts = CertificateAnalysis.ExtractMxHosts(mx).ToArray();
                if (hosts.Length == 0 || Mx.Count == 0) { MxAligned = false; return; }
                foreach (var h in hosts) {
                    if (!Mx.Any(p => PatternMatches(p, h))) {
                        MissingMxFromPolicy.Add(h);
                    }
                }
                MxAligned = MissingMxFromPolicy.Count == 0;
                if (!MxAligned) {
                    Logger?.WriteWarningCode(MtaStsCodes.MxNotAligned, "MTA-STS policy MX patterns do not cover all MX hosts ({0})", string.Join(", ", MissingMxFromPolicy));
                }

                if (ValidMaxAge && MaxAge > 0 && MaxAge < 86400) {
                    Logger?.WriteWarningCode(MtaStsCodes.MaxAgeLow, "MTA-STS max_age {0} is low; consider >= 86400", MaxAge);
                }
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                Logger?.WriteWarningCode(MtaStsCodes.MxAlignmentFailed, "Failed to evaluate MTA-STS MX alignment: {0}", ex.Message);
            }
        }
    }
}
