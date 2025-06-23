using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides functionality for retrieving and analysing MTA-STS policies.
    /// </summary>
    public class MTASTSAnalysis {
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
        /// Resets analysis state so the instance can be reused.
        /// </summary>
        public void Reset() {
            Domain = null;
            PolicyPresent = false;
            PolicyValid = false;
            ValidVersion = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = null;
            MaxAge = 0;
            Mx = new List<string>();
            Policy = null;
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

            string url = PolicyUrlOverride ?? $"https://mta-sts.{domainName}/.well-known/mta-sts.txt";

            string content = await GetPolicy(url);
            if (content == null) {
                PolicyPresent = false;
                return;
            }

            PolicyPresent = true;
            Policy = content;
            ParsePolicy(content);
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

        /// <summary>
        /// Parses the supplied policy text and updates property values.
        /// </summary>
        /// <param name="text">Raw policy text.</param>
        private void ParsePolicy(string text) {
            PolicyValid = true;
            ValidVersion = false;
            ValidMode = false;
            ValidMaxAge = false;
            HasMx = false;
            Mode = null;
            MaxAge = 0;
            Mx = new List<string>();

            var lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
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

                switch (key) {
                    case "version":
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

            PolicyValid = PolicyValid && ValidVersion && ValidMode && ValidMaxAge && HasMx;
        }
    }
}
