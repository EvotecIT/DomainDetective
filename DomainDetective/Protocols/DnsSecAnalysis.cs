using DnsClientX;
using DomainDetective.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Globalization;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace DomainDetective {
    /// <summary>
    /// Provides DNSSEC validation utilities for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsSecAnalysis {
        private readonly List<string> _mismatchSummary = new();

        /// <summary>
        /// Gets a list describing mismatches encountered while validating the
        /// DNSSEC chain.
        /// </summary>
        public IReadOnlyList<string> MismatchSummary => _mismatchSummary;
        /// <summary>Gets the DS records returned for the domain.</summary>
        public IReadOnlyList<string> DsRecords { get; private set; } = new List<string>();

        /// <summary>Gets the DNSKEY records returned for the domain.</summary>
        public IReadOnlyList<string> DnsKeys { get; private set; } = new List<string>();

        /// <summary>Gets the DNSSEC signatures returned for the domain.</summary>
        public IReadOnlyList<string> Signatures { get; private set; } = new List<string>();

        /// <summary>Structured RRSIG records returned for the domain.</summary>
        public IReadOnlyList<RrsigInfo> Rrsigs { get; private set; } = new List<RrsigInfo>();

        /// <summary>Gets a value indicating whether the DNSKEY query returned authentic data.</summary>
        public bool AuthenticData { get; private set; }

        /// <summary>Gets a value indicating whether the DS query returned authentic data.</summary>
        public bool DsAuthenticData { get; private set; }

        /// <summary>Gets a value indicating whether the DS record matches the DNSKEY.</summary>
        public bool DsMatch { get; private set; }

        /// <summary>Gets a value indicating whether the full DNSSEC chain is valid.</summary>
        public bool ChainValid { get; private set; }

        /// <summary>Gets the TTL values for each parent DS record.</summary>
        public IReadOnlyList<int> DsTtls { get; private set; } = new List<int>();

        /// <summary>Gets the key tag of the root trust anchor.</summary>
        public int RootKeyTag { get; private set; }

        /// <summary>Threshold for raising RRSIG expiration warnings.</summary>
        public TimeSpan RrsigExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(14);

        /// <summary>
        /// Performs DNSSEC validation for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to validate.</param>
        /// <param name="logger">Optional logger used for diagnostics.</param>
        /// <param name="dnsConfiguration">Optional DNS configuration.</param>
        public async Task Analyze(string domainName, InternalLogger logger, DnsConfiguration dnsConfiguration = null) {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
            using HttpClient client = new(handler);

            client.DefaultRequestHeaders.Add("Accept", "application/dns-json");

            _mismatchSummary.Clear();
            bool chainValid = true;
            bool first = true;
            string current = domainName;
            List<string> dnsKeys = new();
            List<string> signatures = new();
            List<string> dsRecords = new();
            List<int> dsTtls = new();
            int rootKeyTag = 0;

            while (true) {
                var dnskeyUri = $"https://cloudflare-dns.com/dns-query?name={current}&type=DNSKEY&do=1";
                var dnskeyJson = await client.GetStringAsync(dnskeyUri);
                var dnskeyDoc = JsonDocument.Parse(dnskeyJson);
                bool keyAd = dnskeyDoc.RootElement.TryGetProperty("AD", out var adElem) && adElem.GetBoolean();

                List<string> zoneKeys = new();
                List<string> zoneSigs = new();
                List<RrsigInfo> zoneSigInfos = new();
                if (dnskeyDoc.RootElement.TryGetProperty("Answer", out var ansElem)) {
                    foreach (var answer in ansElem.EnumerateArray()) {
                        var type = answer.GetProperty("type").GetInt32();
                        var data = answer.GetProperty("data").GetString();
                        if (type == 48) {
                            zoneKeys.Add(data);
                        } else if (type == 46) {
                            zoneSigs.Add(data);
                            RrsigInfo sig = ParseRrsig(data);
                            zoneSigInfos.Add(sig);
                            if (sig.Expiration != DateTimeOffset.MinValue &&
                                sig.Expiration - DateTimeOffset.UtcNow <= RrsigExpirationWarningThreshold) {
                                double days = (sig.Expiration - DateTimeOffset.UtcNow).TotalDays;
                                logger?.WriteWarning("RRSIG for {0} expires in {1:F0} days", current, Math.Ceiling(days));
                            }
                        }
                    }
                }

                var dsResult = await FetchDsRecords(current, client);
                dsTtls.Add(dsResult.ttl);

                bool dsMatch = false;
                if (zoneKeys.Count > 0 && dsResult.records.Count > 0) {
                    var ksk = zoneKeys.FirstOrDefault(k => k.StartsWith("257")) ?? zoneKeys[0];
                    dsMatch = VerifyDsMatch(ksk, dsResult.records[0], current);
                }

                foreach (string rec in dsResult.records) {
                    if (!IsDsDigestLengthValid(rec)) {
                        logger?.WriteWarning("DS record for {0} has unexpected digest length", current);
                    }
                    var parts = rec.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) {
                        int alg = AlgorithmNumber(parts[1]);
                        if (!DNSKeyAnalysis.IsValidAlgorithmNumber(alg)) {
                            logger?.WriteWarning("DS record for {0} contains unknown algorithm {1}", current, parts[1]);
                        } else if (DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(alg)) {
                            logger?.WriteWarning("DS record for {0} uses deprecated algorithm {1}", current, parts[1]);
                        }
                    }
                }

                if (!keyAd) {
                    _mismatchSummary.Add($"DNSKEY for {current} not authenticated");
                }
                if (dsResult.records.Count == 0) {
                    _mismatchSummary.Add($"No DS record for {current}");
                } else {
                    if (!dsResult.ad) {
                        _mismatchSummary.Add($"DS for {current} not authenticated");
                    }
                    if (!dsMatch) {
                        _mismatchSummary.Add($"DS mismatch for {current}");
                    }
                }

                if (first) {
                    DnsKeys = zoneKeys;
                    Signatures = zoneSigs;
                    Rrsigs = zoneSigInfos;
                    DsRecords = dsResult.records;
                    AuthenticData = keyAd;
                    DsAuthenticData = dsResult.ad;
                    DsMatch = dsMatch;
                }

                chainValid &= keyAd && dsResult.ad && dsMatch;

                int dot = current.IndexOf('.');
                if (dot == -1) {
                    if (dsResult.records.Count > 0) {
                        string[] rootParts = dsResult.records[0].Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (rootParts.Length > 0 && int.TryParse(rootParts[0], out int tag)) {
                            rootKeyTag = tag;
                        }
                    }
                    break;
                }

                current = current.Substring(dot + 1);
                first = false;
            }

            var anchors = await DownloadTrustAnchors(logger).ConfigureAwait(false);
            if (anchors.Count > 0 && rootKeyTag == 0) {
                string[] parts = anchors[0].Split(' ');
                if (parts.Length > 0 && int.TryParse(parts[0], out int tag)) {
                    rootKeyTag = tag;
                }
            }

            ChainValid = chainValid;
            DsTtls = dsTtls;
            RootKeyTag = rootKeyTag;

            logger?.WriteVerbose("DNSSEC validation for {0}: {1}, chain valid: {2}", domainName, AuthenticData, ChainValid);
        }

        private static async Task<(List<string> records, int ttl, bool ad)> FetchDsRecords(string domain, HttpClient client) {
            var dsUri = $"https://cloudflare-dns.com/dns-query?name={domain}&type=DS&do=1";
            var dsJson = await client.GetStringAsync(dsUri);
            var dsDoc = JsonDocument.Parse(dsJson);
            bool ad = dsDoc.RootElement.TryGetProperty("AD", out var adElem) && adElem.GetBoolean();
            List<string> records = new();
            int ttl = 0;
            if (dsDoc.RootElement.TryGetProperty("Answer", out var dsAnswers)) {
                foreach (var ans in dsAnswers.EnumerateArray()) {
                    if (ans.GetProperty("type").GetInt32() == 43) {
                        records.Add(ans.GetProperty("data").GetString());
                        ttl = ans.GetProperty("TTL").GetInt32();
                    }
                }
            }

            return (records, ttl, ad);
        }

        private static bool IsDsDigestLengthValid(string record) {
            var parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4 || !int.TryParse(parts[2], out int digestType)) {
                return true;
            }

            int expected = digestType switch {
                1 => 40,
                2 => 64,
                4 => 96,
                _ => -1,
            };

            return expected < 0 || parts[3].Length == expected;
        }

        /// <summary>
        /// Validates that the provided DS record matches the specified DNSKEY.
        /// </summary>
        /// <param name="dnskey">DNSKEY record data.</param>
        /// <param name="dsRecord">DS record data.</param>
        /// <param name="domainName">Domain name used in the calculation.</param>
        /// <returns><c>true</c> if the DS record corresponds to the DNSKEY; otherwise <c>false</c>.</returns>
        private static bool VerifyDsMatch(string dnskey, string dsRecord, string domainName) {
            try {
                var keyParts = dnskey.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (keyParts.Length < 4) {
                    return false;
                }

                var flags = ushort.Parse(keyParts[0]);
                var protocol = byte.Parse(keyParts[1]);
                var algorithm = AlgorithmNumber(keyParts[2]);
                if (!DNSKeyAnalysis.IsValidAlgorithmNumber(algorithm)) {
                    return false;
                }
                var publicKeyBytes = Convert.FromBase64String(keyParts[3]);

                var rdata = new List<byte>();
                rdata.AddRange(BitConverter.GetBytes((ushort)flags).Reverse());
                rdata.Add(protocol);
                rdata.Add((byte)algorithm);
                rdata.AddRange(publicKeyBytes);

                var dsParts = dsRecord.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (dsParts.Length < 4) {
                    return false;
                }

                var keyTag = int.Parse(dsParts[0]);
                var dsAlgorithm = AlgorithmNumber(dsParts[1]);
                if (!DNSKeyAnalysis.IsValidAlgorithmNumber(dsAlgorithm)) {
                    return false;
                }
                var digestType = int.Parse(dsParts[2]);
                var digest = dsParts[3];
                if (!DNSKeyAnalysis.IsHexadecimal(digest)) {
                    return false;
                }

                int computedKeyTag = ComputeKeyTag(rdata);
                if (computedKeyTag != keyTag || dsAlgorithm != algorithm) {
                    return false;
                }

                byte[] digestBytes;
                using HashAlgorithm hasher = digestType switch {
                    1 => SHA1.Create(),
                    2 => SHA256.Create(),
                    4 => SHA384.Create(),
                    _ => SHA256.Create(),
                };
                byte[] nameWire = ToWireFormat(domainName);
                var data = new byte[nameWire.Length + rdata.Count];
                nameWire.CopyTo(data, 0);
                rdata.ToArray().CopyTo(data, nameWire.Length);
                digestBytes = hasher.ComputeHash(data);
                var digestHex = BitConverter.ToString(digestBytes).Replace("-", string.Empty).ToLowerInvariant();

                return digestHex.StartsWith(digest.ToLowerInvariant());
            } catch {
                return false;
            }
        }

        /// <summary>
        /// Computes the DNSSEC key tag for the given RDATA sequence.
        /// </summary>
        /// <param name="rdata">RDATA bytes from the DNSKEY record.</param>
        /// <returns>The computed key tag.</returns>
        private static int ComputeKeyTag(List<byte> rdata) {
            int ac = 0;
            for (int i = 0; i < rdata.Count; i++) {
                ac += (i & 1) == 1 ? rdata[i] : rdata[i] << 8;
            }
            ac += (ac >> 16) & 0xFFFF;
            return ac & 0xFFFF;
        }

        /// <summary>
        /// Converts a domain name to its DNS wire format representation.
        /// </summary>
        /// <param name="domainName">Domain name to convert.</param>
        /// <returns>Byte array containing the wire format representation.</returns>
        private static byte[] ToWireFormat(string domainName) {
            domainName = domainName.TrimEnd('.').ToLowerInvariant();
            var labels = domainName.Split('.');
            List<byte> bytes = new();
            foreach (var label in labels) {
                bytes.Add((byte)label.Length);
                bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
            }
            bytes.Add(0);
            return bytes.ToArray();
        }

        /// <summary>
        /// Maps DNS algorithm names to their numeric identifiers.
        /// </summary>
        /// <param name="name">Algorithm name.</param>
        /// <returns>Numeric algorithm identifier.</returns>
        private static int AlgorithmNumber(string name) {
            if (string.IsNullOrWhiteSpace(name)) {
                return 0;
            }

            if (int.TryParse(name, out int numeric)) {
                return DNSKeyAnalysis.IsValidAlgorithmNumber(numeric) ? numeric : 0;
            }

            return name.ToUpperInvariant() switch {
                "RSAMD5" => 1,
                "DH" => 2,
                "DSA" => 3,
                "ECC" => 4,
                "RSASHA1" => 5,
                "DSANSEC3SHA1" => 6,
                "RSASHA1NSEC3SHA1" => 7,
                "RSASHA256" => 8,
                "RSASHA512" => 10,
                "ECCGOST" => 12,
                "ECDSAP256SHA256" => 13,
                "ECDSAP384SHA384" => 14,
                "ED25519" => 15,
                "ED448" => 16,
                "INDIRECT" => 252,
                "PRIVATEDNS" => 253,
                "PRIVATEOID" => 254,
                _ => 0,
            };
        }

        private static RrsigInfo ParseRrsig(string record) {
            if (string.IsNullOrWhiteSpace(record)) {
                return new RrsigInfo();
            }

            string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 7) {
                return new RrsigInfo();
            }

            DateTimeOffset inception = DateTimeOffset.MinValue;
            DateTimeOffset expiration = DateTimeOffset.MinValue;
            if (long.TryParse(parts[5], out long inc)) {
                inception = DateTimeOffset.FromUnixTimeSeconds(inc);
            } else if (DateTimeOffset.TryParseExact(parts[5], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var incDt)) {
                inception = incDt;
            }

            if (long.TryParse(parts[4], out long exp)) {
                expiration = DateTimeOffset.FromUnixTimeSeconds(exp);
            } else if (DateTimeOffset.TryParseExact(parts[4], "yyyyMMddHHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expDt)) {
                expiration = expDt;
            }

            _ = int.TryParse(parts[6], out int keyTag);

            string algorithm = parts[1];
            if (int.TryParse(parts[1], out int algNum)) {
                string name = DNSKeyAnalysis.AlgorithmName(algNum);
                if (!string.IsNullOrEmpty(name)) {
                    algorithm = name;
                }
            }

            return new RrsigInfo {
                Algorithm = algorithm,
                KeyTag = keyTag,
                Inception = inception,
                Expiration = expiration,
            };
        }

        /// <summary>
        /// Downloads the current trust anchors published by IANA.
        /// </summary>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>List of DS record strings for the root zone.</returns>
        public static async Task<IReadOnlyList<string>> DownloadTrustAnchors(InternalLogger logger = null) {
            const string url = "https://data.iana.org/root-anchors/root-anchors.xml";
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");

            try {
                if (File.Exists(cacheFile) && DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile) < TimeSpan.FromDays(7)) {
                    var cached = File.ReadAllText(cacheFile);
                    return ParseTrustAnchors(cached);
                }

                Directory.CreateDirectory(cacheDir);
                using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
                using var client = new HttpClient(handler);
                var xml = await client.GetStringAsync(url).ConfigureAwait(false);
                File.WriteAllText(cacheFile, xml);
                return ParseTrustAnchors(xml);
            } catch (Exception ex) {
                logger?.WriteVerbose("Trust anchor download failed: {0}", ex.Message);
                if (File.Exists(cacheFile)) {
                    var cached = File.ReadAllText(cacheFile);
                    return ParseTrustAnchors(cached);
                }
                return Array.Empty<string>();
            }
        }

        private static IReadOnlyList<string> ParseTrustAnchors(string xml) {
            try {
                var doc = XDocument.Parse(xml);
                List<string> anchors = new();
                foreach (var kd in doc.Descendants("KeyDigest")) {
                    var keyTag = kd.Element("KeyTag")?.Value;
                    var algorithm = kd.Element("Algorithm")?.Value;
                    var digestType = kd.Element("DigestType")?.Value;
                    var digest = kd.Element("Digest")?.Value;
                    if (!string.IsNullOrEmpty(keyTag) && !string.IsNullOrEmpty(algorithm) && !string.IsNullOrEmpty(digestType) && !string.IsNullOrEmpty(digest)) {
                        anchors.Add($"{keyTag} {algorithm} {digestType} {digest}");
                    }
                }
                return anchors;
            } catch {
                return Array.Empty<string>();
            }
        }

        /// <summary>
        /// Validates that the specified record has a valid DNSSEC signature.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="type">Record type to validate.</param>
        /// <returns><c>true</c> when the record is signed and validated; otherwise <c>false</c>.</returns>
        public async Task<bool> ValidateRecord(string domain, DnsRecordType type) {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
            using HttpClient client = new(handler);

            client.DefaultRequestHeaders.Add("Accept", "application/dns-json");

            var queryUri = $"https://cloudflare-dns.com/dns-query?name={domain}&type={(int)type}&do=1";
            var response = await client.GetStringAsync(queryUri);
            using var doc = JsonDocument.Parse(response);
            bool ad = doc.RootElement.TryGetProperty("AD", out var adElem) && adElem.GetBoolean();

            bool hasSig = false;
            if (doc.RootElement.TryGetProperty("Answer", out var answerElem)) {
                foreach (var ans in answerElem.EnumerateArray()) {
                    if (ans.GetProperty("type").GetInt32() == 46) {
                        hasSig = true;
                        break;
                    }
                }
            }

            return ad && hasSig;
        }
    }
}