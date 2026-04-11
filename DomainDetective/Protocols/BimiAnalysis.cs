using DnsClientX;
using System;
using System.Collections.Generic;
using DomainDetective.Helpers;
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
    /// <remarks>
    /// BIMI (Brand Indicators for Message Identification) uses DNS TXT records
    /// that reference an SVG logo file and an optional certificate. This class
    /// validates presence and accessibility of those resources.
    /// </remarks>
public partial class BimiAnalysis : IHasAssessments {
        private const int SvgRequiredDimension = 64;
        private const string SvgRequiredViewBox = "0 0 64 64";
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
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
        /// <summary>Provides a reason when <see cref="SvgValid"/> is <c>false</c>.</summary>
        public string? SvgInvalidReason { get; private set; }
        /// <summary>Gets a value indicating whether the SVG size is within limits.</summary>
        public bool SvgSizeValid { get; private set; }
        /// <summary>Gets a value indicating whether the SVG width and height are correct.</summary>
        public bool DimensionsValid { get; private set; }
        /// <summary>Gets a value indicating whether the SVG viewBox is valid.</summary>
        public bool ViewBoxValid { get; private set; }
        /// <summary>Gets a value indicating whether required SVG attributes are present.</summary>
        public bool SvgAttributesPresent { get; private set; }
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

        /// <summary>Relevant standards for BIMI analysis.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "BIMI (draft)", Reference = "draft-blank-ietf-bimi", Url = "https://datatracker.ietf.org/doc/html/draft-blank-ietf-bimi" }
        };

        /// <summary>Factory for creating custom HTTP handlers.</summary>
        /// <remarks>
        /// Use this only in controlled scenarios (for example, tests that trust
        /// a local self-signed certificate). The default handler performs
        /// platform TLS certificate validation and should remain unchanged for
        /// production checks.
        /// </remarks>
        internal Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

        /// <summary>Skip downloading the BIMI indicator image.</summary>
        public bool SkipIndicatorDownload { get; set; }
        /// <summary>Root certificates considered trusted when validating VMCs.</summary>
        public ICollection<X509Certificate2> TrustedRoots { get; } = new List<X509Certificate2>();

        /// <summary>Structured assessments captured during BIMI analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Actionable recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
        /// Processes BIMI DNS records and populates analysis properties.
        /// </summary>
        /// <param name="dnsResults">TXT records returned from a BIMI DNS query.</param>
        /// <param name="logger">Logger instance for diagnostic output.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeBimiRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "BIMI");
            await Task.Yield();

            ResetState();

            if (dnsResults == null) {
                logger.WriteVerbose("DNS query returned no results.");
                return;
            }

            var recordList = dnsResults.ToList();
            BimiRecordExists = recordList.Any();
            if (!BimiRecordExists) {
                logger.WriteVerbose("No BIMI record found.");
                logger.WriteWarningCode(BimiCodes.MissingRecord, "No BIMI record found.");
                return;
            }
            logger.WriteInformationCode(BimiCodes.RecordPresent, "BIMI record present");

            BimiRecord = string.Join(" ", recordList.Select(r => r.Data));
            logger.WriteVerbose($"Analyzing BIMI record {BimiRecord}");

            ParseBimiHeader(BimiRecord!, logger);
            if (!StartsCorrectly) {
                logger.WriteWarningCode(BimiCodes.StartsInvalid, "BIMI record does not start with v=BIMI1.");
            }

            var location = Location;
            if (location != null && location.Length > 0 && !InvalidLocation) {
                if (!LocationUsesHttps) {
                    logger.WriteWarningCode(BimiCodes.LocationNotHttps, "BIMI indicator location does not use HTTPS: {0}", location);
                }

                if (!SkipIndicatorDownload) {
                    var (svg, size) = await DownloadIndicator(location, logger, cancellationToken);
                    if (svg != null) {
                        SvgFetched = true;
                        SvgValid = ValidateSvg(svg, size, logger);
                        if (SvgValid) {
                            logger.WriteInformationCode(BimiCodes.SvgValid, "BIMI SVG valid");
                        }
                        logger.WriteVerbose("Successfully downloaded BIMI indicator from {0}", location);
                    } else {
                        logger.WriteWarningCode(BimiCodes.DownloadFailed, "Failed to download BIMI indicator from {0}", location);
                    }
                } else {
                    logger.WriteVerbose("Skipping BIMI indicator download");
                }
            }

            var authority = Authority;
            if (authority != null && authority.Length > 0) {
                if (!AuthorityUsesHttps) {
                    logger.WriteWarningCode(BimiCodes.AuthorityNotHttps, "BIMI authority URL does not use HTTPS: {0}", authority);
                }

                (ValidVmc, VmcSignedByKnownRoot, VmcContainsLogo) = await DownloadAndValidateVmc(authority, logger, cancellationToken);
                if (ValidVmc && VmcSignedByKnownRoot) {
                    logger.WriteInformationCode(BimiCodes.VmcVerified, "BIMI certificate valid and trusted");
                }
            }
        }

        /// <summary>
        /// Shared HTTP client that enforces default TLS certificate validation.
        /// </summary>
        private static readonly HttpClient _client;

        static BimiAnalysis()
        {
            _client = HttpClientPlatformFactory.CreateRedirectClient(userAgent: "Mozilla/5.0");
        }

        private (HttpClient client, bool dispose) GetOrCreateClient()
        {
            if (HttpHandlerFactory != null)
            {
                return (new HttpClient(HttpHandlerFactory(), disposeHandler: true), true);
            }

            return (_client, false);
        }

        private async Task<(string? content, int size)> DownloadIndicator(string url, InternalLogger? logger, CancellationToken cancellationToken) {
            try {
                var (client, dispose) = GetOrCreateClient();
                try {
                    using var response = await client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) {
                    return (null, 0);
                }

                var mediaType = response.Content.Headers.ContentType?.MediaType;
                if (!"image/svg+xml".Equals(mediaType, StringComparison.OrdinalIgnoreCase)) {
                    FailureReason = $"Invalid Content-Type: {mediaType}";
                    logger?.WriteWarningCode(BimiCodes.InvalidMimeType, "Invalid BIMI indicator MIME type {0}", mediaType);
                    return (null, 0);
                }

                var bytes = await response.Content.ReadAsByteArrayAsync();
                if (url.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)) {
                    using var ms = new MemoryStream(bytes);
                    using var gz = new GZipStream(ms, CompressionMode.Decompress);
                    using var reader = new StreamReader(gz);
                    var text = await reader.ReadToEndAsync();
                    return (text, System.Text.Encoding.UTF8.GetByteCount(text));
                }
                var str = System.Text.Encoding.UTF8.GetString(bytes);
                    return (str, bytes.Length);
                } finally {
                    if (dispose) {
                        client.Dispose();
                    }
                }
            } catch (HttpRequestException ex) {
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteErrorCode(BimiCodes.DownloadFailed, "HTTP request failed for {0}: {1}", url, ex.Message);
                return (null, 0);
            } catch (Exception ex) {
                logger?.WriteErrorCode(BimiCodes.DownloadFailed, "Error downloading BIMI indicator {0}: {1}", url, ex.Message);
                return (null, 0);
            }
        }

        private async Task<(bool valid, bool signedByKnownRoot, bool hasLogo)> DownloadAndValidateVmc(string url, InternalLogger? logger, CancellationToken cancellationToken) {
            try {
                var (client, dispose) = GetOrCreateClient();
                try {
                    using var response = await client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) {
                    return (false, false, false);
                }

                var bytes = await response.Content.ReadAsByteArrayAsync();
                X509Certificate2 cert;
                try {
                    cert = CertificateLoaderCompat.LoadCertificate(bytes);
                } catch (CryptographicException) {
                    var text = System.Text.Encoding.ASCII.GetString(bytes);
                    var pem = DecodePem(text);
                    cert = CertificateLoaderCompat.LoadCertificate(pem);
                }
                VmcCertificate = cert;
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                var signed = chain.Build(cert);
                var notExpired = cert.NotAfter > DateTime.Now;

                using var trustedChain = new X509Chain();
                trustedChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
#if NET8_0_OR_GREATER
                if (TrustedRoots.Count > 0) {
                    trustedChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    foreach (var root in TrustedRoots) {
                        trustedChain.ChainPolicy.CustomTrustStore.Add(root);
                    }
                }
#endif
                var trusted = trustedChain.Build(cert);
#if NETFRAMEWORK
                if (TrustedRoots.Count > 0) {
                    trusted = IsTrustedByRoots(cert, TrustedRoots);
                }
#endif

                var hasLogo = CertificateHasLogo(cert);

                    return (signed && notExpired, trusted && notExpired, hasLogo);
                } finally {
                    if (dispose) {
                        client.Dispose();
                    }
                }
            } catch (HttpRequestException ex) {
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteErrorCode(BimiCodes.DownloadFailed, "HTTP request failed for {0}: {1}", url, ex.Message);
                return (false, false, false);
            } catch (Exception ex) {
                logger?.WriteErrorCode(BimiCodes.DownloadFailed, "Error downloading BIMI VMC {0}: {1}", url, ex.Message);
                return (false, false, false);
            }
        }

        private bool ValidateSvg(string svgContent, int byteSize, InternalLogger logger) {
            // Draft BIMI specification limits hosted SVG indicators to 32kB
            // https://datatracker.ietf.org/doc/html/draft-blank-ietf-bimi-02#section-4
            const int maxSize = 32 * 1024;
            SvgInvalidReason = null;
            SvgSizeValid = byteSize <= maxSize;
            if (!SvgSizeValid) {
                SvgInvalidReason = $"Indicator exceeds 32 KB ({byteSize} bytes)";
                logger.WriteWarningCode(BimiCodes.SvgTooLarge, "BIMI indicator exceeds 32 KB: {0} bytes", byteSize);
            }

            try {
                var settings = new XmlReaderSettings {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null
                };
                using var reader = XmlReader.Create(new StringReader(svgContent), settings);
                var doc = XDocument.Load(reader);
                var root = doc.Root;
                var isSvg = root?.Name.LocalName.Equals("svg", StringComparison.OrdinalIgnoreCase) == true;
                if (!isSvg) {
                    SvgInvalidReason ??= "Root element is not 'svg'";
                    return false;
                }

                if (root == null)
                {
                    SvgInvalidReason ??= "Malformed SVG";
                    return false;
                }
                var widthAttr = root.Attribute("width");
                var heightAttr = root.Attribute("height");
                var viewBoxAttr = root.Attribute("viewBox");
                SvgAttributesPresent = widthAttr != null && heightAttr != null && viewBoxAttr != null;
                if (!SvgAttributesPresent) {
                    logger.WriteWarningCode(BimiCodes.SvgMissingAttributes, "BIMI SVG missing width, height or viewBox");
                }

                var widthStr = widthAttr?.Value;
                var heightStr = heightAttr?.Value;
                DimensionsValid = int.TryParse(widthStr, out var w) && int.TryParse(heightStr, out var h) && w == SvgRequiredDimension && h == SvgRequiredDimension;
                if (!DimensionsValid) {
                    logger.WriteWarningCode(BimiCodes.SvgWrongDimensions, $"BIMI SVG width and height must be {SvgRequiredDimension}x{SvgRequiredDimension}");
                }

                var viewBox = viewBoxAttr?.Value;
                ViewBoxValid = viewBox == SvgRequiredViewBox;
                if (!ViewBoxValid) {
                    logger.WriteWarningCode(BimiCodes.SvgWrongViewBox, $"BIMI SVG viewBox must be '{SvgRequiredViewBox}'");
                }

                return isSvg && SvgSizeValid;
            } catch {
                SvgInvalidReason ??= "Malformed SVG";
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

#if NETFRAMEWORK
        private static bool IsTrustedByRoots(X509Certificate2 cert, ICollection<X509Certificate2> roots) {
            if (roots == null || roots.Count == 0) {
                return false;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            foreach (var root in roots) {
                chain.ChainPolicy.ExtraStore.Add(root);
            }

            if (!chain.Build(cert) || chain.ChainElements.Count == 0) {
                return false;
            }

            var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            return roots.Any(r => string.Equals(r.Thumbprint, rootCert.Thumbprint, StringComparison.OrdinalIgnoreCase));
        }
#endif

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
            try {
                return Convert.FromBase64String(pem);
            } catch (FormatException ex) {
                throw new FormatException("Invalid PEM data", ex);
            }
        }

    }}
