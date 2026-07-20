using DnsClientX;
using DomainDetective.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.IO;
using System.Text.Json;
using System.Text;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml;

namespace DomainDetective {
    public partial class DnsSecAnalysis : IHasAssessments {
        /// <summary>Executes the download trust anchors operation.</summary>
        public static async Task<(IReadOnlyList<string> anchors, DateTimeOffset? expiration)> DownloadTrustAnchors(
            InternalLogger? logger = null,
            CancellationToken cancellationToken = default,
            string? cacheDirectory = null) {
            const string url = "https://data.iana.org/root-anchors/root-anchors.xml";
            string cacheDir = string.IsNullOrWhiteSpace(cacheDirectory)
                ? Path.Combine(Path.GetTempPath(), "DomainDetective")
                : cacheDirectory!;
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");

            bool fileCreated = false;
            try {
                if (File.Exists(cacheFile) &&
                    DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile) < TimeSpan.FromDays(7)) {
                    if (TryReadCachedTrustAnchors(cacheFile, out string cachedXml)) {
                        return ParseTrustAnchors(cachedXml);
                    }
                }

                Directory.CreateDirectory(cacheDir);
#if NET8_0_OR_GREATER
                using var response = await _client.GetAsync(url, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var xml = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
                using var response = await _client.GetAsync(url, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var xml = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
#endif
                File.WriteAllText(cacheFile, xml, Encoding.UTF8);
                fileCreated = true;
                return ParseTrustAnchors(xml);
            } catch (OperationCanceledException) {
                if (fileCreated && File.Exists(cacheFile)) {
                    File.Delete(cacheFile);
                }
                throw;
            } catch (Exception ex) {
                if (fileCreated && File.Exists(cacheFile)) {
                    File.Delete(cacheFile);
                }
                logger?.WriteVerbose("Trust anchor download failed: {0}", ex.Message);
                if (File.Exists(cacheFile)) {
                    if (TryReadCachedTrustAnchors(cacheFile, out string cachedXml)) {
                        return ParseTrustAnchors(cachedXml);
                    }
                }
                return (Array.Empty<string>(), null);
            }
        }

        private static bool TryReadCachedTrustAnchors(string path, out string xml) {
            xml = string.Empty;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) {
                return false;
            }

            const int maxAttempts = 5;
            for (int attempt = 0; attempt < maxAttempts; attempt++) {
                try {
                    using var stream = new FileStream(
                        path,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(stream, Encoding.UTF8, true);
                    xml = reader.ReadToEnd();
                    return !string.IsNullOrWhiteSpace(xml);
                } catch (IOException) when (attempt < maxAttempts - 1) {
                    Thread.Sleep(50 * (attempt + 1));
                } catch (UnauthorizedAccessException) when (attempt < maxAttempts - 1) {
                    Thread.Sleep(50 * (attempt + 1));
                }
            }

            return false;
        }

        private static (IReadOnlyList<string> anchors, DateTimeOffset? expiration) ParseTrustAnchors(string xml) {
            if (string.IsNullOrWhiteSpace(xml) || !IsXmlWellFormed(xml)) {
                return (Array.Empty<string>(), null);
            }

            try {
                var doc = XDocument.Parse(xml);

                var digests = new List<(string Ds, DateTimeOffset? ValidFrom, DateTimeOffset? ValidUntil)>();
                foreach (var kd in doc.Descendants("KeyDigest")) {
                    var keyTag = kd.Element("KeyTag")?.Value;
                    var algorithm = kd.Element("Algorithm")?.Value;
                    var digestType = kd.Element("DigestType")?.Value;
                    var digest = kd.Element("Digest")?.Value;

                    if (string.IsNullOrWhiteSpace(keyTag) ||
                        string.IsNullOrWhiteSpace(algorithm) ||
                        string.IsNullOrWhiteSpace(digestType) ||
                        string.IsNullOrWhiteSpace(digest)) {
                        continue;
                    }

                    DateTimeOffset? validFrom = null;
                    var validFromRaw = kd.Attribute("validFrom")?.Value;
                    if (!string.IsNullOrWhiteSpace(validFromRaw) && DateTimeOffset.TryParse(validFromRaw, out var vf)) {
                        validFrom = vf;
                    }

                    DateTimeOffset? validUntil = null;
                    var validUntilRaw = kd.Attribute("validUntil")?.Value;
                    if (!string.IsNullOrWhiteSpace(validUntilRaw) && DateTimeOffset.TryParse(validUntilRaw, out var vu)) {
                        validUntil = vu;
                    }

                    digests.Add(($"{keyTag} {algorithm} {digestType} {digest}", validFrom, validUntil));
                }

                if (digests.Count == 0) {
                    return (Array.Empty<string>(), null);
                }

                var now = DateTimeOffset.UtcNow;
                var active = digests
                    .Where(d => (!d.ValidFrom.HasValue || now >= d.ValidFrom.Value) &&
                                (!d.ValidUntil.HasValue || now < d.ValidUntil.Value))
                    .ToList();

                var selected = active.Count > 0 ? active : digests;
                var anchors = selected.Select(x => x.Ds).ToList();

                DateTimeOffset? expiration = null;
                foreach (var d in selected) {
                    if (!d.ValidUntil.HasValue) {
                        continue;
                    }
                    if (!expiration.HasValue || d.ValidUntil.Value < expiration.Value) {
                        expiration = d.ValidUntil.Value;
                    }
                }

                return (anchors, expiration);
            } catch {
                return (Array.Empty<string>(), null);
            }
        }

        private static bool IsXmlWellFormed(string xml) {
            try {
                using var reader = XmlReader.Create(new StringReader(xml));
                while (reader.Read()) {
                    // Just read through to validate well-formedness
                }
                return true;
            } catch {
                return false;
            }
        }

        /// <summary>
        /// Validates that the specified record has a valid DNSSEC signature.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="type">Record type to validate.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns><c>true</c> when the record is signed and validated; otherwise <c>false</c>.</returns>
        public async Task<bool> ValidateRecord(string domain, DnsRecordType type, CancellationToken ct = default) {
            return await ValidateRecord(domain, type, dnsConfiguration: null, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Validates the specified record through the configured resolver without leaking private names
        /// to an implicit list of public fallback services.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="type">Record type to validate.</param>
        /// <param name="dnsConfiguration">Optional resolver configuration; the system resolver is used when omitted.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns><c>true</c> only when DnsClientX reports a locally authenticated secure result.</returns>
        public async Task<bool> ValidateRecord(string domain, DnsRecordType type,
            DnsConfiguration? dnsConfiguration, CancellationToken ct = default) {
            Func<string, DnsRecordType, CancellationToken, Task<DnsResponse>>? responseOverride =
                QueryDnsResponseOverride ?? dnsConfiguration?.QueryDnsResponseOverride;
            DnsEndpoint[] endpoints = dnsConfiguration?.DnsEndpoints.Count > 0
                ? dnsConfiguration.DnsEndpoints.Distinct().ToArray()
                : new[] { dnsConfiguration?.DnsEndpoint ?? DnsEndpoint.System };
            using DnsMultiResolver? resolver = responseOverride == null
                ? CreateResolver(endpoints, validateDnsSec: true)
                : null;
            DnsResponse response = await Resolve(
                resolver, domain, type, responseOverride, ct).ConfigureAwait(false);
            return response.DnsSecValidationStatus == DnsSecValidationStatus.Secure;
        }
    }
}
