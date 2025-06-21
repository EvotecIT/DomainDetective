using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective {
    public class DNSSecAnalysis {
        public IReadOnlyList<string> DsRecords { get; private set; } = new List<string>();
        public IReadOnlyList<string> DnsKeys { get; private set; } = new List<string>();
        public IReadOnlyList<string> Signatures { get; private set; } = new List<string>();
        public bool AuthenticData { get; private set; }
        public bool DsMatch { get; private set; }

        public async Task Analyze(string domainName, InternalLogger logger, DnsConfiguration dnsConfiguration = null) {
            using HttpClient client = new();

            var dnskeyUri = $"https://cloudflare-dns.com/dns-query?name={domainName}&type=DNSKEY&do=1";
            client.DefaultRequestHeaders.Add("Accept", "application/dns-json");
            var dnskeyJson = await client.GetStringAsync(dnskeyUri);
            var dnskeyDoc = JsonDocument.Parse(dnskeyJson);
            AuthenticData = dnskeyDoc.RootElement.GetProperty("AD").GetBoolean();

            var answers = dnskeyDoc.RootElement.GetProperty("Answer").EnumerateArray();
            var dnskeys = new List<string>();
            var rrsigs = new List<string>();
            foreach (var answer in answers) {
                var type = answer.GetProperty("type").GetInt32();
                var data = answer.GetProperty("data").GetString();
                if (type == 48) { // DNSKEY
                    dnskeys.Add(data);
                } else if (type == 46) { // RRSIG
                    rrsigs.Add(data);
                }
            }

            DnsKeys = dnskeys;
            Signatures = rrsigs;

            var dsUri = $"https://cloudflare-dns.com/dns-query?name={domainName}&type=DS&do=1";
            var dsJson = await client.GetStringAsync(dsUri);
            var dsDoc = JsonDocument.Parse(dsJson);
            var dsAnswers = dsDoc.RootElement.GetProperty("Answer").EnumerateArray();
            var dsRecords = new List<string>();
            foreach (var ans in dsAnswers) {
                if (ans.GetProperty("type").GetInt32() == 43) {
                    dsRecords.Add(ans.GetProperty("data").GetString());
                }
            }
            DsRecords = dsRecords;

            if (DnsKeys.Count > 0 && DsRecords.Count > 0) {
                var ksk = DnsKeys.FirstOrDefault(k => k.StartsWith("257")) ?? DnsKeys[0];
                DsMatch = VerifyDsMatch(ksk, DsRecords[0]);
            }

            logger?.WriteVerbose("DNSSEC validation for {0}: {1}", domainName, AuthenticData);
        }

        private static bool VerifyDsMatch(string dnskey, string dsRecord) {
            try {
                var keyParts = dnskey.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (keyParts.Length < 4) {
                    return false;
                }

                var flags = ushort.Parse(keyParts[0]);
                var protocol = byte.Parse(keyParts[1]);
                var algorithm = AlgorithmNumber(keyParts[2]);
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
                var digestType = int.Parse(dsParts[2]);
                var digest = dsParts[3];

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
                digestBytes = hasher.ComputeHash(rdata.ToArray());
                var digestHex = BitConverter.ToString(digestBytes).Replace("-", string.Empty).ToLowerInvariant();

                return digestHex.StartsWith(digest.ToLowerInvariant());
            } catch {
                return false;
            }
        }

        private static int ComputeKeyTag(List<byte> rdata) {
            int ac = 0;
            for (int i = 0; i < rdata.Count; i++) {
                ac += (i & 1) == 1 ? rdata[i] : rdata[i] << 8;
            }
            ac += (ac >> 16) & 0xFFFF;
            return ac & 0xFFFF;
        }

        private static int AlgorithmNumber(string name) => name.ToUpperInvariant() switch {
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
}