using DnsClientX;
using DomainDetective.Protocols;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml;

namespace DomainDetective {
    /// <summary>
    /// Provides DNSSEC validation utilities for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Using dnsclientx the full DNSSEC chain is retrieved and validated
    /// against DS records from the parent zone.
    /// </remarks>
    public class DnsSecAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        private readonly List<string> _mismatchSummary = new();
        private readonly List<string> _warnings = new();

        /// <summary>
        /// Gets a list describing mismatches encountered while validating the
        /// DNSSEC chain.
        /// </summary>
        public IReadOnlyList<string> MismatchSummary => _mismatchSummary;
        /// <summary>Collection of warning messages.</summary>
        public IReadOnlyList<string> Warnings => _warnings;
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

        /// <summary>Threshold for raising key expiration warnings.</summary>
        public TimeSpan KeyExpirationWarningThreshold { get; set; } = TimeSpan.FromDays(30);

        /// <summary>Indicates whether any key expires soon.</summary>
        public bool KeyExpiresSoon { get; private set; }

        /// <summary>Expiration date for the root trust anchor.</summary>
        public DateTimeOffset? RootAnchorExpiration { get; private set; }

        /// <summary>Structured assessments captured during DNSSEC validation.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
        /// Performs DNSSEC validation for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to validate.</param>
        /// <param name="logger">Optional logger used for diagnostics.</param>
        /// <param name="dnsConfiguration">Optional DNS configuration.</param>
        private static readonly HttpClient _client;

        static DnsSecAnalysis()
        {
            var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 };
            _client = new HttpClient(handler, disposeHandler: false);
            _client.DefaultRequestHeaders.Add("Accept", "application/dns-json");
        }

        public async Task Analyze(string domainName, InternalLogger logger, DnsConfiguration? dnsConfiguration = null, CancellationToken ct = default) {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSSEC", target: domainName) : null;
            Subject = domainName;
            var client = _client;

            _mismatchSummary.Clear();
            _warnings.Clear();
            KeyExpiresSoon = false;
            RootAnchorExpiration = null;
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
                using var dnskeyResponse = await client.GetAsync(dnskeyUri, ct).ConfigureAwait(false);
                dnskeyResponse.EnsureSuccessStatusCode();
                var dnskeyJson = await dnskeyResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
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
                                sig.Expiration - DateTimeOffset.UtcNow <= KeyExpirationWarningThreshold) {
                                double days = (sig.Expiration - DateTimeOffset.UtcNow).TotalDays;
                                string message = string.Format(
                                    CultureInfo.InvariantCulture,
                                    "RRSIG for {0} expires in {1:F0} days",
                                    current,
                                    Math.Ceiling(days));
                                logger?.WriteWarningCode(DnssecCodes.RrsigExpiring, message);
                                _warnings.Add(message);
                                KeyExpiresSoon = true;
                            }
                        }
                    }
                }

                var dsResult = await FetchDsRecords(current, client, ct);
                dsTtls.Add(dsResult.ttl);

                List<string> currentDsRecords = dsResult.records ?? new List<string>();

                bool dsMatch = false;
                if (zoneKeys.Count > 0 && currentDsRecords.Count > 0) {
                    var ksk = zoneKeys.FirstOrDefault(k => k.StartsWith("257")) ?? zoneKeys[0];
                    dsMatch = VerifyDsMatch(ksk, currentDsRecords[0], current);
                }

                foreach (string rec in currentDsRecords) {
                    if (!IsDsDigestLengthValid(rec)) {
                        logger?.WriteWarningCode(DnssecCodes.DsDigestLengthUnexpected, "DS record for {0} has unexpected digest length", current);
                    }
                    var parts = rec.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) {
                        int alg = AlgorithmNumber(parts[1]);
                        if (!DNSKeyAnalysis.IsValidAlgorithmNumber(alg)) {
                            logger?.WriteWarningCode(DnssecCodes.DsAlgorithmUnknown, "DS record for {0} contains unknown algorithm {1}", current, parts[1]);
                        } else if (DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(alg)) {
                            logger?.WriteWarningCode(DnssecCodes.DsAlgorithmDeprecated, "DS record for {0} uses deprecated algorithm {1}", current, parts[1]);
                        }
                    }
                }

                if (!keyAd) {
                    var msg = $"DNSKEY for {current} not authenticated";
                    _mismatchSummary.Add(msg);
                    logger?.WriteWarningCode(DnssecCodes.DnskeyNotAuthenticated, msg);
                }
                if (currentDsRecords.Count == 0) {
                    var msg = $"No DS record for {current}";
                    _mismatchSummary.Add(msg);
                    logger?.WriteWarningCode(DnssecCodes.DsMissing, msg);
                } else {
                    if (!dsResult.ad) {
                        var msg = $"DS for {current} not authenticated";
                        _mismatchSummary.Add(msg);
                        logger?.WriteWarningCode(DnssecCodes.DsNotAuthenticated, msg);
                    }
                    if (!dsMatch) {
                        var msg = $"DS mismatch for {current}";
                        _mismatchSummary.Add(msg);
                        logger?.WriteWarningCode(DnssecCodes.DsMismatch, msg);
                    }
                }

                if (first) {
                    DnsKeys = zoneKeys;
                    Signatures = zoneSigs;
                    Rrsigs = zoneSigInfos;
                    DsRecords = currentDsRecords;
                    AuthenticData = keyAd;
                    DsAuthenticData = dsResult.ad;
                    DsMatch = dsMatch;
                }

                chainValid &= keyAd && dsResult.ad && dsMatch;

                int dot = current.IndexOf('.');
                if (dot == -1) {
                    if (currentDsRecords.Count > 0) {
                        string[] rootParts = currentDsRecords[0].Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (rootParts.Length > 0 && int.TryParse(rootParts[0], out int tag)) {
                            rootKeyTag = tag;
                        }
                    }
                    break;
                }

                current = current.Substring(dot + 1);
                first = false;
            }

            var anchorResult = await DownloadTrustAnchors(logger, ct).ConfigureAwait(false);
            var anchors = anchorResult.anchors;
            RootAnchorExpiration = anchorResult.expiration;
            if (anchors.Count > 0 && rootKeyTag == 0) {
                string[] parts = anchors[0].Split(' ');
                if (parts.Length > 0 && int.TryParse(parts[0], out int tag)) {
                    rootKeyTag = tag;
                }
            }

            if (RootAnchorExpiration.HasValue) {
                double days = (RootAnchorExpiration.Value - DateTimeOffset.UtcNow).TotalDays;
                if (days <= 0) {
                    string message = string.Format(
                        CultureInfo.InvariantCulture,
                        "Root trust anchor expired {0:F0} days ago",
                        Math.Ceiling(Math.Abs(days)));
                    logger?.WriteWarningCode(DnssecCodes.RootAnchorExpired, message);
                    _warnings.Add(message);
                    KeyExpiresSoon = true;
                } else if (days <= KeyExpirationWarningThreshold.TotalDays) {
                    string message = string.Format(
                        CultureInfo.InvariantCulture,
                        "Root trust anchor expires in {0:F0} days",
                        Math.Ceiling(days));
                    logger?.WriteWarningCode(DnssecCodes.RootAnchorExpiring, message);
                    _warnings.Add(message);
                    KeyExpiresSoon = true;
                }
            }

            ChainValid = chainValid;
            DsTtls = dsTtls;
            RootKeyTag = rootKeyTag;

            logger?.WriteVerbose("DNSSEC validation for {0}: {1}, chain valid: {2}", domainName, AuthenticData, ChainValid);

            // Check NSEC3/NSEC3PARAM for Opt-Out usage (risk advisory)
            try {
                if (await HasNsec3OptOutAsync(domainName, ct).ConfigureAwait(false)) {
                    logger?.WriteWarningCode(DnssecCodes.Nsec3OptOutRisk, "Zone uses NSEC3 Opt-Out");
                }
            } catch (Exception ex) {
                logger?.WriteDebug("NSEC3 Opt-Out check skipped: {0}", ex.Message);
            }

            if (ChainValid) {
                logger?.WriteInformationCode(DnssecCodes.SignaturesValid, "DNSSEC signatures validated");
                logger?.WriteInformationCode(DnssecCodes.ChainValid, "DNSSEC chain validated");
            }
        }

        private static async Task<bool> HasNsec3OptOutAsync(string domain, CancellationToken ct) {
            using var respParam = await _client.GetAsync($"https://cloudflare-dns.com/dns-query?name={domain}&type=51&do=1", ct).ConfigureAwait(false);
            if (respParam.IsSuccessStatusCode) {
                var json = await respParam.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("Answer", out var answers)) {
                    foreach (var ans in answers.EnumerateArray()) {
                        if (ans.GetProperty("type").GetInt32() == 51) {
                            var data = ans.GetProperty("data").GetString(); // NSEC3PARAM: Hash Flags Iterations Salt
                            if (!string.IsNullOrWhiteSpace(data)) {
                                var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            // Fallback: check NSEC3 record flags
            using var resp = await _client.GetAsync($"https://cloudflare-dns.com/dns-query?name={domain}&type=50&do=1", ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return false;
            var json3 = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc3 = JsonDocument.Parse(json3);
            if (doc3.RootElement.TryGetProperty("Answer", out var ans3)) {
                foreach (var ans in ans3.EnumerateArray()) {
                    if (ans.GetProperty("type").GetInt32() == 50) {
                        var data = ans.GetProperty("data").GetString(); // NSEC3: Hash Flags Iterations Salt Next TypeBitMaps
                        if (!string.IsNullOrWhiteSpace(data)) {
                            var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 2 && int.TryParse(parts[1], out var flags) && (flags & 0x01) != 0) {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        private static async Task<(List<string> records, int ttl, bool ad)> FetchDsRecords(string domain, HttpClient client, CancellationToken ct) {
            var dsUri = $"https://cloudflare-dns.com/dns-query?name={domain}&type=DS&do=1";
            using var dsResponse = await client.GetAsync(dsUri, ct).ConfigureAwait(false);
            dsResponse.EnsureSuccessStatusCode();
            var dsJson = await dsResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
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
            if (string.IsNullOrWhiteSpace(dnskey) || string.IsNullOrWhiteSpace(dsRecord)) {
                return false;
            }
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

                int computedKeyTag = ComputeKeyTag(dnskey);
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
        /// Computes the DNSSEC key tag from a DNSKEY record.
        /// </summary>
        /// <param name="dnskeyRecord">Full DNSKEY record string.</param>
        /// <returns>Key tag value or 0 if parsing fails.</returns>
        public static int ComputeKeyTag(string dnskeyRecord) {
            if (string.IsNullOrWhiteSpace(dnskeyRecord)) {
                return 0;
            }

            var parts = dnskeyRecord.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) {
                return 0;
            }

            if (!ushort.TryParse(parts[0], out ushort flags) ||
                !byte.TryParse(parts[1], out byte protocol)) {
                return 0;
            }

            int algorithm = AlgorithmNumber(parts[2]);
            if (!DNSKeyAnalysis.IsValidAlgorithmNumber(algorithm)) {
                return 0;
            }

            byte[] publicKeyBytes = Convert.FromBase64String(parts[3]);
            List<byte> rdata = new();
            rdata.AddRange(BitConverter.GetBytes(flags).Reverse());
            rdata.Add(protocol);
            rdata.Add((byte)algorithm);
            rdata.AddRange(publicKeyBytes);

            return ComputeKeyTag(rdata);
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

        private static bool VerifyEcdsaSignature(string key, string signature, byte[] data, int algorithm) {
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(signature) || data == null) {
                return false;
            }

            try {
                byte[] pub = Convert.FromBase64String(key);
                byte[] sig = Convert.FromBase64String(signature);
                int fieldSize = algorithm == 14 ? 48 : 32;
                if (pub.Length != fieldSize * 2 || sig.Length != fieldSize * 2) {
                    return false;
                }

                ECParameters p = new() {
                    Curve = algorithm == 14 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint {
                        X = pub.AsSpan(0, fieldSize).ToArray(),
                        Y = pub.AsSpan(fieldSize, fieldSize).ToArray(),
                    }
                };

                using ECDsa ecdsa = ECDsa.Create(p);
                HashAlgorithmName hash = algorithm == 14 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
                return ecdsa.VerifyData(data, sig, hash);
            } catch {
                return false;
            }
        }

        private static byte[] P1363ToDer(byte[] signature, int size) {
            int half = signature.Length / 2;
            byte[] r = new byte[half];
            byte[] s = new byte[half];
            Array.Copy(signature, 0, r, 0, half);
            Array.Copy(signature, half, s, 0, half);

            r = TrimLeadingZeros(r);
            s = TrimLeadingZeros(s);

            if (r[0] >= 0x80) {
                r = PrependZero(r);
            }
            if (s[0] >= 0x80) {
                s = PrependZero(s);
            }

            int len = 2 + r.Length + 2 + s.Length;
            byte[] der = new byte[len + 2];
            int pos = 0;
            der[pos++] = 0x30;
            der[pos++] = (byte)len;
            der[pos++] = 0x02;
            der[pos++] = (byte)r.Length;
            Array.Copy(r, 0, der, pos, r.Length);
            pos += r.Length;
            der[pos++] = 0x02;
            der[pos++] = (byte)s.Length;
            Array.Copy(s, 0, der, pos, s.Length);
            return der;
        }

        private static byte[] TrimLeadingZeros(byte[] value) {
            int i = 0;
            while (i < value.Length - 1 && value[i] == 0) {
                i++;
            }
            if (i == 0) {
                return value;
            }

            byte[] output = new byte[value.Length - i];
            Array.Copy(value, i, output, 0, output.Length);
            return output;
        }

        private static byte[] PrependZero(byte[] value) {
            byte[] output = new byte[value.Length + 1];
            output[0] = 0;
            Array.Copy(value, 0, output, 1, value.Length);
            return output;
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
        public static async Task<(IReadOnlyList<string> anchors, DateTimeOffset? expiration)> DownloadTrustAnchors(
            InternalLogger? logger = null,
            CancellationToken cancellationToken = default) {
            const string url = "https://data.iana.org/root-anchors/root-anchors.xml";
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");

            bool fileCreated = false;
            try {
                if (File.Exists(cacheFile) &&
                    DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile) < TimeSpan.FromDays(7)) {
                    var cached = File.ReadAllText(cacheFile);
                    return ParseTrustAnchors(cached);
                }

                Directory.CreateDirectory(cacheDir);
#if NET6_0_OR_GREATER
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
                    var cached = File.ReadAllText(cacheFile);
                    return ParseTrustAnchors(cached);
                }
                return (Array.Empty<string>(), null);
            }
        }

        private static (IReadOnlyList<string> anchors, DateTimeOffset? expiration) ParseTrustAnchors(string xml) {
            if (string.IsNullOrWhiteSpace(xml) || !IsXmlWellFormed(xml)) {
                return (Array.Empty<string>(), null);
            }

            try {
                var doc = XDocument.Parse(xml);
                List<string> anchors = new();
                DateTimeOffset? earliest = null;
                foreach (var kd in doc.Descendants("KeyDigest")) {
                    var keyTag = kd.Element("KeyTag")?.Value;
                    var algorithm = kd.Element("Algorithm")?.Value;
                    var digestType = kd.Element("DigestType")?.Value;
                    var digest = kd.Element("Digest")?.Value;
                    var validUntil = kd.Attribute("validUntil")?.Value;
                    if (!string.IsNullOrEmpty(keyTag) && !string.IsNullOrEmpty(algorithm) && !string.IsNullOrEmpty(digestType) && !string.IsNullOrEmpty(digest)) {
                        anchors.Add($"{keyTag} {algorithm} {digestType} {digest}");
                    }
                    if (DateTimeOffset.TryParse(validUntil, out var exp)) {
                        if (earliest == null || exp < earliest) {
                            earliest = exp;
                        }
                    }
                }
                return (anchors, earliest);
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
        /// <returns><c>true</c> when the record is signed and validated; otherwise <c>false</c>.</returns>
        public async Task<bool> ValidateRecord(string domain, DnsRecordType type, CancellationToken ct = default) {
            var client = _client;

            var queryUri = $"https://cloudflare-dns.com/dns-query?name={domain}&type={(int)type}&do=1";
            using var response = await client.GetAsync(queryUri, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);
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
    }}
