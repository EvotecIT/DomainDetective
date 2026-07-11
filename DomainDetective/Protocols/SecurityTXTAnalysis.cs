using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Downloads and validates security.txt files according to the specification.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public class SecurityTXTAnalysis : IHasAssessments {
        private record CacheEntry(string Content, string Url, bool FallbackUsed, DateTimeOffset Expires);
        private record DownloadResult(string Content, string Url);
        private static readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
        private const int MaxRedirects = 10;

        /// <summary>
        /// Clears cached security.txt content used across instances.
        /// </summary>
        public static void ClearCache() => _cache.Clear();
        /// <summary>Domain that was analyzed.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>True when a security.txt record was found.</summary>
        public bool RecordPresent { get; set; }

        /// <summary>True when the record passed validation.</summary>
        public bool RecordValid { get; set; }

        /// <summary>Indicates the record is signed with PGP.</summary>
        public bool PGPSigned { get; set; }

        /// <summary>Set when fallback retrieval method was used.</summary>
        public bool FallbackUsed { get; set; }

        /// <summary>URL from which the record was downloaded.</summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>Gets the duplicate tags value.</summary>
        public HashSet<string> DuplicateTags { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Fields that can appear multiple times as List<string>
        /// <summary>Gets or sets the contact email value.</summary>
        public List<string> ContactEmail { get; set; } = new List<string>();
        /// <summary>Gets or sets the contact website value.</summary>
        public List<string> ContactWebsite { get; set; } = new List<string>();
        /// <summary>Gets or sets the acknowledgments value.</summary>
        public List<string> Acknowledgments { get; set; } = new List<string>();
        /// <summary>Gets or sets the preferred languages value.</summary>
        public List<string> PreferredLanguages { get; set; } = new List<string>();
        /// <summary>Gets or sets the encryption value.</summary>
        public List<string> Encryption { get; set; } = new List<string>();
        /// <summary>Gets or sets the policy value.</summary>
        public List<string> Policy { get; set; } = new List<string>();
        /// <summary>Gets or sets the hiring value.</summary>
        public List<string> Hiring { get; set; } = new List<string>();

        // Fields that should only appear once as string
        /// <summary>Gets or sets the canonical value.</summary>
        public List<string> Canonical { get; set; } = new List<string>();
        /// <summary>Gets or sets the expires value.</summary>
        public string Expires { get; set; } = string.Empty;
        /// <summary>Gets or sets the signature encryption value.</summary>
        public string SignatureEncryption { get; set; } = string.Empty;


        internal InternalLogger Logger { get; set; } = new InternalLogger();
        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
        /// <summary>Optional factory used to create a constrained outbound HTTP handler.</summary>
        public Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }


        /// <summary>
        /// Retrieves and parses the security.txt file for the given domain.
        /// </summary>
        public async Task AnalyzeSecurityTxtRecord(string domainName, InternalLogger logger, string? pgpPublicKey = null, CancellationToken cancellationToken = default) {
            Logger = logger;
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SECURITYTXT", target: domainName);

            if (!Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out _)) {
                throw new ArgumentException("Invalid host name.", nameof(domainName));
            }

            Domain = domainName;

            if (_cache.TryGetValue(domainName, out var entry) && entry.Expires > DateTimeOffset.UtcNow) {
                RecordPresent = true;
                Url = entry.Url;
                FallbackUsed = entry.FallbackUsed;
                ParseSecurityTxt(entry.Content, pgpPublicKey, entry.Url);
                return;
            }

            string url = $"https://{domainName}/.well-known/security.txt";
            var download = await GetSecurityTxt(url, cancellationToken);
            bool fallback = false;
            if (download == null) {
                url = $"http://{domainName}/security.txt";
                download = await GetSecurityTxt(url, cancellationToken);
                fallback = true;
            }

            if (download != null) {
                var response = download.Content;
                url = download.Url;
                RecordPresent = true;
                Url = url;
                FallbackUsed = fallback;
                Logger?.WriteInformationCode(SecurityTxtCodes.RecordPresent, "security.txt present");
                ParseSecurityTxt(response, pgpPublicKey, url);

                if (DateTimeOffset.TryParse(Expires, out var expires)) {
                    entry = new CacheEntry(response, url, fallback, expires);
                } else {
                    entry = new CacheEntry(response, url, fallback, DateTimeOffset.UtcNow.AddHours(1));
                }

                _cache[domainName] = entry;
            }
        }

        /// <summary>
        /// Downloads the security.txt file from the specified URL.
        /// </summary>
        private static readonly HttpClient _client;

        static SecurityTXTAnalysis()
        {
            _client = HttpClientPlatformFactory.CreateRedirectClient(
                userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537");
        }

        private async Task<DownloadResult?> GetSecurityTxt(string url, CancellationToken cancellationToken) {
            try {
                if (HttpHandlerFactory == null) {
                    using var response = await _client.GetAsync(url, cancellationToken).ConfigureAwait(false);
                    if (response.IsSuccessStatusCode && response.Content.Headers.ContentType?.MediaType == "text/plain") {
                        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        return new DownloadResult(content, response.RequestMessage?.RequestUri?.AbsoluteUri ?? url);
                    }
                    return null;
                }

                using var client = new HttpClient(HttpHandlerFactory(), disposeHandler: true);
                var currentUri = new Uri(url);
                var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var redirects = 0; redirects <= MaxRedirects; redirects++) {
                    if (!visited.Add(currentUri.AbsoluteUri)) {
                        throw new InvalidOperationException("security.txt redirect loop detected.");
                    }

                    using var response = await client.GetAsync(currentUri, cancellationToken).ConfigureAwait(false);
                    if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
                        if (redirects == MaxRedirects) {
                            throw new InvalidOperationException($"Maximum number of security.txt redirects ({MaxRedirects}) exceeded.");
                        }
                        currentUri = response.Headers.Location.IsAbsoluteUri
                            ? response.Headers.Location
                            : new Uri(currentUri, response.Headers.Location);
                        continue;
                    }

                    if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "text/plain") {
                        return null;
                    }

                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    return new DownloadResult(content, currentUri.AbsoluteUri);
                }

                return null;
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                Logger?.WriteDebug("Failed to download security.txt from {0}: {1}", url, ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Parses the contents of a security.txt file.
        /// </summary>
        private void ParseSecurityTxt(string txt, string? pgpPublicKey, string currentUrl) {
            if (txt.Contains("-----BEGIN PGP SIGNED MESSAGE-----")) {
                PGPSigned = true;
                if (!string.IsNullOrEmpty(pgpPublicKey)) {
                    try {
                        if (DomainDetectiveOptionalFeatures.TryVerifySecurityTxtSignature(txt, pgpPublicKey, out bool isVerified, out string verifiedClearText)) {
                            if (!isVerified) {
                                Logger.WriteWarningCode(SecurityTxtCodes.SignatureVerifyFailed, "PGP signature verification failed");
                            }
                            txt = verifiedClearText;
                        } else {
                            Logger.WriteWarningCode(
                                SecurityTxtCodes.SignatureVerifyFailed,
                                "PGP signature found but no verifier is registered. Install DomainDetective.Pgp and call DomainDetectivePgpRegistration.Register().");
                            txt = ExtractClearText(txt);
                        }
                    } catch (Exception ex) {
                        Logger.WriteWarningCode(SecurityTxtCodes.SignatureVerifyFailed, $"PGP signature verification failed: {ex.Message}");
                        txt = ExtractClearText(txt);
                    }
                } else {
                    Logger.WriteWarningCode(SecurityTxtCodes.SignatureVerifyFailed, "PGP signature found but no public key was provided for verification.");
                    txt = ExtractClearText(txt);
                }
            }

            var lines = txt.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            RecordValid = true;
            DuplicateTags.Clear();
            var seenTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool hasSeenExpires = false;
            bool hasSeenSignatureEncryption = false;

            foreach (var line in lines) {
                // Ignore comments
                if (line.StartsWith("#")) {
                    continue;
                }

                // Check if this line starts with a field name
                int colonIndex = line.IndexOf(':');
                if (colonIndex > 0) {
                    string currentField = line.Substring(0, colonIndex).Trim();
                    string value = line.Substring(colonIndex + 1).Trim();

                    if (!seenTags.Add(currentField)) {
                        DuplicateTags.Add(currentField);
                        RecordValid = false;
                    }

                    // Add the value to the appropriate list in the record
                    switch (currentField.ToLowerInvariant()) {
                        case "contact":
                            if (value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                                var emailPart = value.Substring("mailto:".Length);
                                try {
                                    var address = new MailAddress(emailPart);
                                    ContactEmail.Add(address.Address);
                                } catch (FormatException) {
                                    Logger.WriteWarningCode(SecurityTxtCodes.InvalidEmail, "Invalid email format in Contact field");
                                    RecordValid = false;
                                }
                            } else if (Uri.TryCreate(value, UriKind.Absolute, out var contactUri)) {
                                if (string.Equals(contactUri.Scheme, "http", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(contactUri.Scheme, "https", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(contactUri.Scheme, "tel", StringComparison.OrdinalIgnoreCase)) {
                                    ContactWebsite.Add(contactUri.ToString());
                                } else {
                                    Logger.WriteWarningCode(SecurityTxtCodes.InvalidUriScheme, "Unrecognized URI scheme in Contact field");
                                    RecordValid = false;
                                }
                            } else if (value.Contains("@")) {
                                try {
                                    var address = new MailAddress(value);
                                    ContactEmail.Add(address.Address);
                                } catch (FormatException) {
                                    Logger.WriteWarningCode(SecurityTxtCodes.InvalidEmail, "Invalid email format in Contact field");
                                    RecordValid = false;
                                }
                            } else {
                                Logger.WriteWarningCode(SecurityTxtCodes.InvalidContactFormat, "Invalid Contact field format");
                                RecordValid = false;
                            }
                            break;
                        case "acknowledgments":
                            Acknowledgments.Add(value);
                            break;
                        case "preferred-languages":
                            PreferredLanguages.Add(value);
                            break;
                        case "encryption":
                            Encryption.Add(value);
                            break;
                        case "policy":
                            Policy.Add(value);
                            break;
                        case "hiring":
                            Hiring.Add(value);
                            break;
                        case "canonical":
                            Canonical.Add(value);
                            break;
                        case "expires":
                            if (hasSeenExpires) {
                                Logger.WriteWarningCode(SecurityTxtCodes.MultipleExpires, "Multiple Expires fields found");
                                RecordValid = false;
                            }
                            Expires = value;
                            hasSeenExpires = true;
                            break;
                        case "signature-encryption":
                            if (hasSeenSignatureEncryption) {
                                Logger.WriteWarningCode(SecurityTxtCodes.MultipleSignatureEncryption, "Multiple Signature-Encryption fields found");
                                RecordValid = false;
                            }
                            SignatureEncryption = value;
                            hasSeenSignatureEncryption = true;
                            break;

                    }
                }
            }

            if (ContactEmail.Count == 0 && ContactWebsite.Count == 0) {
                Logger.WriteWarningCode(SecurityTxtCodes.MissingContact, "Missing required Contact field");
                RecordValid = false;
            }

            if (!hasSeenExpires) {
                Logger.WriteWarningCode(SecurityTxtCodes.MissingExpires, "Missing required Expires field");
                RecordValid = false;
            } else {
                if (!DateTime.TryParse(Expires, out DateTime expiresDate)) {
                    Logger.WriteWarningCode(SecurityTxtCodes.InvalidExpiresFormat, "Invalid Expires date format");
                    RecordValid = false;
                } else {
                    if (expiresDate < DateTime.UtcNow) {
                        Logger.WriteWarningCode(SecurityTxtCodes.ExpiresPast, "Expires date is in the past");
                        RecordValid = false;
                    }
                    if (expiresDate > DateTime.UtcNow.AddYears(1)) {
                        Logger.WriteWarningCode(SecurityTxtCodes.ExpiresTooFarFuture, "Expires date more than one year in the future");
                        RecordValid = false;
                    }
                }
            }

            if (Canonical.Count > 0) {
                foreach (var canonicalUrl in Canonical) {
                    if (!canonicalUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                        Logger.WriteWarningCode(SecurityTxtCodes.CanonicalNotHttps, "Canonical URL must start with https://");
                        RecordValid = false;
                    }
                }

                if (!Canonical.Exists(c => string.Equals(c.TrimEnd('/'), currentUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))) {
                    Logger.WriteWarningCode(SecurityTxtCodes.CanonicalMismatch, "Canonical URL does not match retrieved file location");
                    RecordValid = false;
                }
            }

            if (!RecordValid) {
                Logger.WriteWarningCode(SecurityTxtCodes.InvalidFile, "Invalid security.txt file");
            } else {
                Logger.WriteInformationCode(SecurityTxtCodes.RecordValid, "security.txt syntax valid");
            }
        }

        /// <summary>
        /// Extracts clear text from a PGP signed message.
        /// </summary>
        private string ExtractClearText(string signedText) {
            const string header = "-----BEGIN PGP SIGNED MESSAGE-----";
            const string signatureHeader = "-----BEGIN PGP SIGNATURE-----";
            int headerIndex = signedText.IndexOf(header);
            if (headerIndex == -1)
                return signedText;

            int headerEnd = signedText.IndexOf("\n\n", headerIndex);
            if (headerEnd == -1)
                headerEnd = signedText.IndexOf("\r\n\r\n", headerIndex);
            if (headerEnd == -1)
                return signedText;

            int sigIndex = signedText.IndexOf(signatureHeader, headerEnd);
            if (sigIndex == -1)
                return signedText;

            return signedText.Substring(headerEnd + 2, sigIndex - headerEnd - 2).Trim();
        }

    }
}
