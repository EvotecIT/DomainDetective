using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace DomainDetective {
    /// <summary>
    /// Analyse BIMI records according to draft specifications.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class BimiAnalysis {
        /// <summary>Gets the concatenated BIMI record text.</summary>
        public string? BimiRecord { get; private set; }
        /// <summary>Gets a value indicating whether a BIMI record was found.</summary>
        public bool BimiRecordExists { get; private set; }
        /// <summary>Gets a value indicating whether the record starts with <c>v=BIMI1</c>.</summary>
        public bool StartsCorrectly { get; private set; }
        /// <summary>Gets the indicator location value if present.</summary>
        public string? Location { get; private set; }
        /// <summary>Gets the authority indicator URL if present.</summary>
        public string? Authority { get; private set; }
        /// <summary>Gets a value indicating whether <see cref="Location"/> uses HTTPS.</summary>
        public bool LocationUsesHttps { get; private set; }
        /// <summary>Gets a value indicating whether <see cref="Authority"/> uses HTTPS.</summary>
        public bool AuthorityUsesHttps { get; private set; }
        /// <summary>Gets a value indicating whether the domain opted out of publishing an indicator.</summary>
        public bool DeclinedToPublish { get; private set; }
        /// <summary>Gets a value indicating whether <see cref="Location"/> uses an unsupported scheme or file type.</summary>
        public bool InvalidLocation { get; private set; }
        /// <summary>Gets a value indicating whether the indicator SVG file was downloaded.</summary>
        public bool SvgFetched { get; private set; }
        /// <summary>Gets a value indicating whether the downloaded SVG is valid.</summary>
        public bool SvgValid { get; private set; }
        /// <summary>Gets a value indicating whether the downloaded VMC is valid.</summary>
        public bool ValidVmc { get; private set; }
        /// <summary>Gets a value indicating whether the VMC certificate is signed by a trusted CA.</summary>
        public bool VmcSignedByKnownRoot { get; private set; }
        /// <summary>Gets a value indicating whether the VMC contains a logotype.</summary>
        public bool VmcContainsLogo { get; private set; }
        /// <summary>Gets the downloaded VMC certificate instance.</summary>
        public X509Certificate2? VmcCertificate { get; private set; }
        /// <summary>If an HTTP request fails, explains why.</summary>
        public string? FailureReason { get; private set; }

        /// <summary>
        /// Processes BIMI DNS records and populates analysis properties.
        /// </summary>
        /// <param name="dnsResults">TXT records returned from a BIMI DNS query.</param>
        /// <param name="logger">Logger instance for diagnostic output.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeBimiRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            await Task.Yield();

            BimiRecord = null;
            BimiRecordExists = false;
            StartsCorrectly = false;
            Location = null;
            Authority = null;
            LocationUsesHttps = false;
            AuthorityUsesHttps = false;
            DeclinedToPublish = false;
            InvalidLocation = false;
            SvgFetched = false;
            SvgValid = false;
            ValidVmc = false;
            VmcSignedByKnownRoot = false;
            VmcContainsLogo = false;
            VmcCertificate = null;
            FailureReason = null;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var recordList = dnsResults.ToList();
            BimiRecordExists = recordList.Any();
            if (!BimiRecordExists) {
                logger.WriteVerbose("No BIMI record found.");
                return;
            }

            BimiRecord = string.Join(" ", recordList.Select(r => r.Data));
            logger.WriteVerbose($"Analyzing BIMI record {BimiRecord}");

            StartsCorrectly = BimiRecord?.StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase) == true;

            foreach (var part in (BimiRecord ?? string.Empty).Split(';')) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();

                switch (key) {
                    case "l":
                        Location = value;
                        InvalidLocation = !(value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                            && (value.EndsWith(".svg", StringComparison.OrdinalIgnoreCase)
                                || value.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)));
                        if (InvalidLocation) {
                            logger?.WriteWarning("Invalid BIMI indicator location {0}", value);
                        }
                        break;
                    case "a":
                        Authority = value;
                        break;
                }
            }

            LocationUsesHttps = string.IsNullOrEmpty(Location) || Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            AuthorityUsesHttps = string.IsNullOrEmpty(Authority) || Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

            DeclinedToPublish = string.IsNullOrEmpty(Location) && string.IsNullOrEmpty(Authority);

            if (!string.IsNullOrEmpty(Location) && !InvalidLocation) {
                if (!LocationUsesHttps) {
                    logger?.WriteWarning("BIMI indicator location does not use HTTPS: {0}", Location);
                }

                var svg = await DownloadIndicator(Location, logger, cancellationToken);
                if (svg != null) {
                    SvgFetched = true;
                    SvgValid = ValidateSvg(svg);
                    logger?.WriteVerbose("Successfully downloaded BIMI indicator from {0}", Location);
                } else {
                    logger?.WriteWarning("Failed to download BIMI indicator from {0}", Location);
                }
            }

            if (!string.IsNullOrEmpty(Authority)) {
                if (!AuthorityUsesHttps) {
                    logger?.WriteWarning("BIMI authority URL does not use HTTPS: {0}", Authority);
                }

                (ValidVmc, VmcSignedByKnownRoot, VmcContainsLogo) = await DownloadAndValidateVmc(Authority, logger, cancellationToken);
            }
        }

        private async Task<string?> DownloadIndicator(string url, InternalLogger logger, CancellationToken cancellationToken) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
#if NET6_0_OR_GREATER
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
#endif
                using var client = new HttpClient(handler);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                using var response = await client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) {
                    return null;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync();
                if (url.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)) {
                    using var ms = new MemoryStream(bytes);
                    using var gz = new GZipStream(ms, CompressionMode.Decompress);
                    using var reader = new StreamReader(gz);
                    return await reader.ReadToEndAsync();
                }
                return System.Text.Encoding.UTF8.GetString(bytes);
            } catch (HttpRequestException ex) {
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteError("HTTP request failed for {0}: {1}", url, ex.Message);
                return null;
            } catch (Exception ex) {
                logger?.WriteError("Error downloading BIMI indicator {0}: {1}", url, ex.Message);
                return null;
            }
        }

        private async Task<(bool valid, bool signedByKnownRoot, bool hasLogo)> DownloadAndValidateVmc(string url, InternalLogger logger, CancellationToken cancellationToken) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
#if NET6_0_OR_GREATER
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
#endif
                using var client = new HttpClient(handler);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                using var response = await client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) {
                    return (false, false, false);
                }

                var bytes = await response.Content.ReadAsByteArrayAsync();
                X509Certificate2 cert;
                try {
                    cert = new X509Certificate2(bytes);
                } catch (CryptographicException) {
                    var text = System.Text.Encoding.ASCII.GetString(bytes);
                    var pem = DecodePem(text);
                    cert = new X509Certificate2(pem);
                }
                VmcCertificate = cert;
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                var signed = chain.Build(cert);
                var notExpired = cert.NotAfter > DateTime.Now;

                using var trustedChain = new X509Chain();
                trustedChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                var trusted = trustedChain.Build(cert);

                var hasLogo = CertificateHasLogo(cert);

                return (signed && notExpired, trusted && notExpired, hasLogo);
            } catch (HttpRequestException ex) {
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteError("HTTP request failed for {0}: {1}", url, ex.Message);
                return (false, false, false);
            } catch (Exception ex) {
                logger?.WriteError("Error downloading BIMI VMC {0}: {1}", url, ex.Message);
                return (false, false, false);
            }
        }

        private static bool ValidateSvg(string svgContent) {
            try {
                var settings = new XmlReaderSettings {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null
                };
                using var reader = XmlReader.Create(new StringReader(svgContent), settings);
                var doc = XDocument.Load(reader);
                return doc.Root?.Name.LocalName.Equals("svg", StringComparison.OrdinalIgnoreCase) == true;
            } catch {
                return false;
            }
        }

        private static bool CertificateHasLogo(X509Certificate2 cert) {
            foreach (var ext in cert.Extensions) {
                var oid = ext.Oid?.Value;
                if (oid == "1.3.6.1.5.5.7.1.12" || oid == "1.3.6.1.5.5.7.1.26") {
                    var text = System.Text.Encoding.ASCII.GetString(ext.RawData);
                    if (text.Contains("image/svg") || text.Contains("image/png")) {
                        return true;
                    }
                }
            }
            return false;
        }

        private static byte[] DecodePem(string pem) {
            const string header = "-----BEGIN CERTIFICATE-----";
            const string footer = "-----END CERTIFICATE-----";
            var start = pem.IndexOf(header, StringComparison.Ordinal);
            if (start >= 0) {
                start += header.Length;
                var end = pem.IndexOf(footer, start, StringComparison.Ordinal);
                if (end >= 0) {
                    pem = pem.Substring(start, end - start);
                }
            }
            pem = pem.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            return Convert.FromBase64String(pem);
        }
    }
}