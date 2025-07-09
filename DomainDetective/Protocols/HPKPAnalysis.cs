using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes HTTP Public Key Pinning (HPKP) headers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class HPKPAnalysis {
        /// <summary>Gets a value indicating whether the Public-Key-Pins header was present.</summary>
        public bool HeaderPresent { get; private set; }
        /// <summary>Gets a value indicating whether all retrieved pins were syntactically valid.</summary>
        public bool PinsValid { get; private set; }
        /// <summary>Gets the max-age directive value.</summary>
        public int MaxAge { get; private set; }
        /// <summary>Gets a value indicating whether the includeSubDomains directive was present.</summary>
        public bool IncludesSubDomains { get; private set; }
        /// <summary>Gets the list of SHA-256 pin values.</summary>
        public List<string> Pins { get; private set; } = new();
        /// <summary>Gets the raw header value.</summary>
        public string? Header { get; private set; }

        /// <summary>
        /// Gets or sets a value indicating that the certificate is self-signed.
        /// When true a single pin is considered sufficient and will not cause
        /// <see cref="PinsValid"/> to be false.
        /// </summary>
        public bool SelfSignedCertificate { get; set; }

        /// <summary>
        /// Performs an HTTP request to retrieve the Public-Key-Pins header and
        /// verifies that any advertised pins are valid base64-encoded SHA-256
        /// hashes.
        /// </summary>
        /// <param name="url">The URL to request.</param>
        /// <param name="logger">Logger used for error reporting.</param>
        private static readonly HttpClient _client;

        static HPKPAnalysis()
        {
            var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
            _client = new HttpClient(handler, disposeHandler: false);
        }

        public async Task AnalyzeUrl(string url, InternalLogger logger) {
            HeaderPresent = false;
            PinsValid = false;
            Pins = new List<string>();
            Header = null;
            MaxAge = 0;
            IncludesSubDomains = false;

            try {
                using var response = await _client.GetAsync(url);
                if (response.Headers.TryGetValues("Public-Key-Pins", out var values)) {
                    Header = string.Join(";", values);
                }
                HeaderPresent = !string.IsNullOrEmpty(Header);
                if (!HeaderPresent) {
                    return;
                }

                logger?.WriteWarning("HPKP header found but HPKP is obsolete (RFC 7469).");

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
                    } else if (trimmed.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase)) {
                        var value = trimmed.Substring(8);
                        if (int.TryParse(value, out var ma)) {
                            MaxAge = ma;
                        }
                    } else if (string.Equals(trimmed, "includeSubDomains", StringComparison.OrdinalIgnoreCase)) {
                        IncludesSubDomains = true;
                    }
                }
                PinsValid = valid && (SelfSignedCertificate ? Pins.Count >= 1 : Pins.Count >= 2);
            } catch (Exception ex) {
                logger?.WriteError("HPKP check failed for {0}: {1}", url, ex.Message);
            }
        }
    }
}