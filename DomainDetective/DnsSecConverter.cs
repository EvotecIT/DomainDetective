using System;
using System.Collections.Generic;
using DomainDetective.Protocols;

namespace DomainDetective {
    /// <summary>
    ///     Helper methods to convert <see cref="DnsSecAnalysis"/> results into
    ///     strongly typed objects.
    /// </summary>
    public static class DnsSecConverter {
        private static DnsAlgorithm MapAlgorithmNumber(int number) {
            return number switch {
                0 => DnsAlgorithm.DELETE,
                1 => DnsAlgorithm.RSAMD5,
                2 => DnsAlgorithm.DH,
                3 => DnsAlgorithm.DSA,
                4 => DnsAlgorithm.ECC,
                5 => DnsAlgorithm.RSASHA1,
                6 => DnsAlgorithm.DSANSEC3SHA1,
                7 => DnsAlgorithm.RSASHA1NSEC3SHA1,
                8 => DnsAlgorithm.RSASHA256,
                9 => DnsAlgorithm.RESERVED9,
                10 => DnsAlgorithm.RSASHA512,
                11 => DnsAlgorithm.RESERVED11,
                12 => DnsAlgorithm.ECCGOST,
                13 => DnsAlgorithm.ECDSAP256SHA256,
                14 => DnsAlgorithm.ECDSAP384SHA384,
                15 => DnsAlgorithm.ED25519,
                16 => DnsAlgorithm.ED448,
                17 => DnsAlgorithm.SM2SM3,
                23 => DnsAlgorithm.ECC_GOST12,
                252 => DnsAlgorithm.INDIRECT,
                253 => DnsAlgorithm.PRIVATEDNS,
                254 => DnsAlgorithm.PRIVATEOID,
                255 => DnsAlgorithm.RESERVED255,
                _ => DnsAlgorithm.Unknown,
            };
        }

        /// <summary>
        ///     Builds a <see cref="DnsSecInfo"/> object from analysis data.
        /// </summary>
        /// <param name="analysis">DNSSEC analysis instance.</param>
        /// <returns>Structured representation of the results.</returns>
        public static DnsSecInfo Convert(DnsSecAnalysis analysis) {
            List<DsRecordInfo> dsRecords = new();
            if (analysis.DsRecords != null) {
                foreach (string record in analysis.DsRecords) {
                    dsRecords.Add(ParseDsRecord(record));
                }
            }

            List<DnsKeyInfo> dnsKeys = new();
            if (analysis.DnsKeys != null) {
                foreach (string key in analysis.DnsKeys) {
                    dnsKeys.Add(ParseDnsKey(key));
                }
            }

            List<RrsigInfo> rrsigs = new();
            if (analysis.Rrsigs != null) {
                rrsigs.AddRange(analysis.Rrsigs);
            }

            return new DnsSecInfo {
                DsRecords = dsRecords,
                DnsKeys = dnsKeys,
                Signatures = analysis.Signatures,
                Rrsigs = rrsigs,
                AuthenticData = analysis.AuthenticData,
                DsAuthenticData = analysis.DsAuthenticData,
                DsMatch = analysis.DsMatch,
                ChainValid = analysis.ChainValid,
                DsTtls = analysis.DsTtls,
                RootKeyTag = analysis.RootKeyTag,
                MismatchSummary = analysis.MismatchSummary
            };
        }

        private static DsRecordInfo ParseDsRecord(string record) {
            if (string.IsNullOrWhiteSpace(record)) {
                return new DsRecordInfo();
            }

            string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) {
                return new DsRecordInfo { Digest = record };
            }

            _ = int.TryParse(parts[0], out int keyTag);
            _ = int.TryParse(parts[2], out int digestType);
            DnsAlgorithm algorithm = DnsAlgorithm.Unknown;
            if (int.TryParse(parts[1], out int algNum)) {
                algorithm = MapAlgorithmNumber(algNum);
            } else if (Enum.TryParse(parts[1].Replace("-", "_"), true, out DnsAlgorithm parsed)) {
                algorithm = parsed;
            }
            return new DsRecordInfo {
                KeyTag = keyTag,
                Algorithm = algorithm,
                DigestType = digestType,
                Digest = parts[3],
            };
        }

        private static DnsKeyInfo ParseDnsKey(string record) {
            if (string.IsNullOrWhiteSpace(record)) {
                return new DnsKeyInfo();
            }

            string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) {
                return new DnsKeyInfo { PublicKey = record };
            }

            _ = int.TryParse(parts[0], out int flags);
            _ = byte.TryParse(parts[1], out byte protocol);
            DnsAlgorithm algorithm = DnsAlgorithm.Unknown;
            if (int.TryParse(parts[2], out int algNum)) {
                algorithm = MapAlgorithmNumber(algNum);
            } else if (Enum.TryParse(parts[2].Replace("-", "_"), true, out DnsAlgorithm parsed)) {
                algorithm = parsed;
            }
            return new DnsKeyInfo {
                Flags = flags,
                Protocol = protocol,
                Algorithm = algorithm,
                PublicKey = parts[3],
            };
        }
    }

    /// <summary>
    ///     DNSSEC validation results in a simplified form.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// The class aggregates DS, DNSKEY and RRSIG information for easy
    /// consumption by tools that don't require full record details.
    /// </remarks>
    public class DnsSecInfo {
        /// <summary>Returned DS records.</summary>
        public IReadOnlyList<DsRecordInfo> DsRecords { get; set; }

        /// <summary>Returned DNSKEY records.</summary>
        public IReadOnlyList<DnsKeyInfo> DnsKeys { get; set; }

        /// <summary>DNSSEC signature records.</summary>
        public IReadOnlyList<string> Signatures { get; set; }

        /// <summary>Structured RRSIG records.</summary>
        public IReadOnlyList<RrsigInfo> Rrsigs { get; set; }

        /// <summary>True when the DNSKEY query had the AD flag set.</summary>
        public bool AuthenticData { get; set; }

        /// <summary>True when the DS query had the AD flag set.</summary>
        public bool DsAuthenticData { get; set; }

        /// <summary>Indicates whether the DS record matches the DNSKEY.</summary>
        public bool DsMatch { get; set; }

        /// <summary>True when the entire DNSSEC chain validated.</summary>
        public bool ChainValid { get; set; }

        /// <summary>TTL values for each DS lookup in the validation chain.</summary>
        public IReadOnlyList<int> DsTtls { get; set; }

        /// <summary>Key tag for the root trust anchor.</summary>
        public int RootKeyTag { get; set; }

        /// <summary>Descriptions of any mismatches encountered.</summary>
        public IReadOnlyList<string> MismatchSummary { get; set; }
    }

    /// <summary>
    ///     Simplified representation of a DS record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Information is derived from standard DNS record text.</remarks>
    public class DsRecordInfo {
        /// <summary>Key tag value.</summary>
        public int KeyTag { get; set; }

        /// <summary>Algorithm used to generate the signature.</summary>
        public DnsAlgorithm Algorithm { get; set; }

        /// <summary>Digest type identifier.</summary>
        public int DigestType { get; set; }

        /// <summary>Digest hex string.</summary>
        public string Digest { get; set; }
    }

    /// <summary>
    ///     Simplified representation of a DNSKEY record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Only the fields relevant for display and analysis are retained.
    /// </remarks>
    public class DnsKeyInfo {
        /// <summary>Record flags.</summary>
        public int Flags { get; set; }

        /// <summary>Protocol value.</summary>
        public byte Protocol { get; set; }

        /// <summary>Algorithm used to generate the key.</summary>
        public DnsAlgorithm Algorithm { get; set; }

        /// <summary>Base64 encoded public key.</summary>
        public string PublicKey { get; set; }
    }

    /// <summary>
    ///     Simplified representation of an RRSIG record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Contains timing information useful for detecting signature rollovers.
    /// </remarks>
    public class RrsigInfo {
        /// <summary>Key tag value.</summary>
        public int KeyTag { get; set; }

        /// <summary>Algorithm used to sign the record.</summary>
        public DnsAlgorithm Algorithm { get; set; }

        /// <summary>Signature inception time.</summary>
        public DateTimeOffset Inception { get; set; }

        /// <summary>Signature expiration time.</summary>
        public DateTimeOffset Expiration { get; set; }

        /// <summary>Days remaining until the signature expires.</summary>
        public double DaysRemaining => (Expiration - DateTimeOffset.UtcNow).TotalDays;
    }
}