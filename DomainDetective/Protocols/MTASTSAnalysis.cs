using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides functionality for retrieving and analysing MTA-STS policies.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public class MTASTSAnalysis {
    private record CacheEntry(string PolicyId, string Policy, DateTimeOffset Expires);
    private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Duration a cached policy remains valid.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Removes all cached policies.</summary>
    public static void ClearCache() => _cache.Clear();
        /// <summary>
        /// Gets the domain name that was analysed.
        /// </summary>
        public string Domain { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy was successfully fetched.
        /// </summary>
        public bool PolicyPresent { get; private set; }

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
        public string Mode { get; private set; }

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
        public string Policy { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the policy enforces MTA-STS.
        /// </summary>
        public bool EnforcesMtaSts => PolicyValid && string.Equals(Mode, "enforce", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Gets or sets the logger instance used for reporting warnings.
        /// </summary>
        internal InternalLogger Logger { get; set; }

        /// <summary>
        /// Gets or sets a policy URL override. When set, this URL is used
        /// instead of constructing one from the domain name. Primarily
        /// intended for testing.
        /// </summary>
        public string PolicyUrlOverride { get; set; }

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

        /// <summary>
        /// Gets a value indicating whether the TXT record is valid.
        /// </summary>
        public bool DnsRecordValid { get; private set; }

        /// <summary>
        /// Gets the policy ID extracted from the TXT record.
        /// </summary>
        public string PolicyId { get; private set; }

        /// <summary>
        /// Resets analysis state so the instance can be reused.
        /// </summary>
        public void Reset() {
            Domain = null;
            PolicyPresent = false;
            PolicyValid = false;
            ValidVersion = false;
            VersionPresent = false;
            HasDuplicateFields = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = null;
            MaxAge = 0;
            Mx = new List<string>();
            Policy = null;
            DnsRecordPresent = false;
            DnsRecordValid = false;
            PolicyId = null;
        }

        /// <summary>
        /// Fetches and analyses the policy for the specified domain using HTTPS.
        /// </summary>
        /// <param name="domainName">The domain to query.</param>
        /// <param name="logger">A logger for warning messages.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        public async Task AnalyzePolicy(string domainName, InternalLogger logger) {
            Reset();
            Logger = logger;
            Domain = domainName;

            var dns = await QueryDns($"_mta-sts.{domainName}", DnsRecordType.TXT);
            DnsRecordPresent = dns?.Any() == true;
            if (!DnsRecordPresent) {
                PolicyValid = false;
                return;
            }

            ParseDnsRecord(string.Join(string.Empty, dns.Select(r => r.Data)));
            if (!DnsRecordValid) {
                PolicyValid = false;
                return;
            }

            string url = PolicyUrlOverride ?? $"https://mta-sts.{domainName}/.well-known/mta-sts.txt";
            var key = PolicyUrlOverride ?? domainName;

            if (_cache.TryGetValue(key, out var entry) && entry.Expires > DateTimeOffset.UtcNow && entry.PolicyId == PolicyId) {
                PolicyPresent = true;
                Policy = entry.Policy;
                ParsePolicy(entry.Policy);
                PolicyValid = PolicyValid && DnsRecordValid;
                return;
            }

            string content = await GetPolicy(url);
            if (content == null) {
                PolicyPresent = false;
                PolicyValid = false;
                return;
            }

            PolicyPresent = true;
            Policy = content;
            ParsePolicy(content);
            PolicyValid = PolicyValid && DnsRecordValid;
            var cacheEntry = new CacheEntry(PolicyId, content, DateTimeOffset.UtcNow.Add(CacheDuration));
            _cache[key] = cacheEntry;
        }

        /// <summary>
        /// Analyses the supplied policy text.
        /// </summary>
        /// <param name="text">Raw policy contents.</param>
        public void AnalyzePolicyText(string text) {
            Reset();
            ParsePolicy(text);
        }

        /// <summary>
        /// Retrieves the policy contents from the specified URL.
        /// </summary>
        /// <param name="url">The policy URL.</param>
        /// <returns>The policy text or <see langword="null"/> if the request failed.</returns>
        private async Task<string> GetPolicy(string url) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using HttpClient client = new(handler);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                var response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode) {
                    return await response.Content.ReadAsStringAsync();
                }
            } catch (Exception ex) {
                Logger?.WriteWarning($"Failed to fetch {url}: {ex.Message}");
            }

            return null;
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        private void ParseDnsRecord(string record) {
            DnsRecordValid = false;
            PolicyId = null;
            if (string.IsNullOrWhiteSpace(record)) {
                return;
            }

            var parts = record.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            bool hasVersion = false;
            foreach (var part in parts) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();
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
            HasDuplicateFields = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = null;
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
    }
}