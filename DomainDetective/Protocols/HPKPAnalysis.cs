using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    public class HPKPAnalysis {
        public bool HeaderPresent { get; private set; }
        public bool PinsValid { get; private set; }
        public List<string> Pins { get; private set; } = new();
        public string? Header { get; private set; }

        public async Task AnalyzeUrl(string url, InternalLogger logger) {
            HeaderPresent = false;
            PinsValid = false;
            Pins = new List<string>();
            Header = null;

            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using var client = new HttpClient(handler);
                using var response = await client.GetAsync(url);
                if (response.Headers.TryGetValues("Public-Key-Pins", out var values)) {
                    Header = string.Join(";", values);
                }
                HeaderPresent = !string.IsNullOrEmpty(Header);
                if (!HeaderPresent) {
                    return;
                }

                var parts = (Header ?? string.Empty).Split(';');
                var valid = true;
                foreach (var part in parts) {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("pin-sha256=\"", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith("\"")) {
                        var b64 = trimmed.Substring(12, trimmed.Length - 13);
                        Pins.Add(b64);
                        try {
                            var bytes = Convert.FromBase64String(b64);
                            if (bytes.Length != 32) {
                                valid = false;
                            }
                        } catch (FormatException) {
                            valid = false;
                        }
                    }
                }
                PinsValid = valid && Pins.Count > 0;
            } catch (Exception ex) {
                logger?.WriteError("HPKP check failed for {0}: {1}", url, ex.Message);
            }
        }
    }
}