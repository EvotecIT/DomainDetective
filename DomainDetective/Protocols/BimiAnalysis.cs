using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective {
    /// <summary>
    /// Analyse BIMI records according to draft specifications.
    /// </summary>
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
        /// <summary>Gets a value indicating whether the indicator SVG file was downloaded.</summary>
        public bool SvgFetched { get; private set; }
        /// <summary>Gets a value indicating whether the downloaded SVG is valid.</summary>
        public bool SvgValid { get; private set; }
        /// <summary>Gets a value indicating whether the downloaded VMC is valid.</summary>
        public bool ValidVmc { get; private set; }

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
            SvgFetched = false;
            SvgValid = false;
            ValidVmc = false;

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
                        break;
                    case "a":
                        Authority = value;
                        break;
                }
            }

            LocationUsesHttps = string.IsNullOrEmpty(Location) || Location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            AuthorityUsesHttps = string.IsNullOrEmpty(Authority) || Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

            DeclinedToPublish = string.IsNullOrEmpty(Location) && string.IsNullOrEmpty(Authority);

            if (!string.IsNullOrEmpty(Location)) {
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

                ValidVmc = await DownloadAndValidateVmc(Authority, logger, cancellationToken);
            }
        }

        private static async Task<string> DownloadIndicator(string url, InternalLogger logger, CancellationToken cancellationToken) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using (HttpClient client = new HttpClient(handler)) {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                    using (var response = await client.GetAsync(url, cancellationToken)) {
                        if (!response.IsSuccessStatusCode) {
                            return null;
                        }

                        var bytes = await response.Content.ReadAsByteArrayAsync();
                        if (url.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)) {
                            using (var ms = new MemoryStream(bytes))
                            using (var gz = new GZipStream(ms, CompressionMode.Decompress))
                            using (var reader = new StreamReader(gz)) {
                                return await reader.ReadToEndAsync();
                            }
                        }
                        return System.Text.Encoding.UTF8.GetString(bytes);
                    }
                }
            } catch (Exception ex) {
                logger?.WriteError("Error downloading BIMI indicator {0}: {1}", url, ex.Message);
                return null;
            }
        }

        private static async Task<bool> DownloadAndValidateVmc(string url, InternalLogger logger, CancellationToken cancellationToken) {
            try {
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using var client = new HttpClient(handler);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");
                using var response = await client.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) {
                    return false;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync();
                var cert = new X509Certificate2(bytes);
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                var signed = chain.Build(cert);
                var notExpired = cert.NotAfter > DateTime.Now;
                return signed && notExpired;
            } catch (Exception ex) {
                logger?.WriteError("Error downloading BIMI VMC {0}: {1}", url, ex.Message);
                return false;
            }
        }

        private static bool ValidateSvg(string svgContent) {
            try {
                var doc = XDocument.Parse(svgContent);
                return doc.Root?.Name.LocalName.Equals("svg", StringComparison.OrdinalIgnoreCase) == true;
            } catch {
                return false;
            }
        }
    }
}