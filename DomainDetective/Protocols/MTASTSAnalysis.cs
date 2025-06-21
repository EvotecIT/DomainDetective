using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    public class MTASTSAnalysis {
        public string Domain { get; private set; }
        public bool PolicyPresent { get; private set; }
        public bool PolicyValid { get; private set; }
        public bool ValidVersion { get; private set; }
        public bool ValidMode { get; private set; }
        public bool ValidMaxAge { get; private set; }
        public bool HasMx { get; private set; }
        public string Mode { get; private set; }
        public int MaxAge { get; private set; }
        public List<string> Mx { get; private set; } = new List<string>();
        public string Policy { get; private set; }

        internal InternalLogger Logger { get; set; }

        public async Task AnalyzePolicy(string domainName, InternalLogger logger) {
            Logger = logger;
            Domain = domainName;
            string url = $"https://mta-sts.{domainName}/.well-known/mta-sts.txt";
            string content = await GetPolicy(url);
            if (content == null) {
                PolicyPresent = false;
                return;
            }

            PolicyPresent = true;
            Policy = content;
            ParsePolicy(content);
        }

        public void AnalyzePolicyText(string text) => ParsePolicy(text);

        private async Task<string> GetPolicy(string url) {
            try {
                using HttpClient client = new();
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
