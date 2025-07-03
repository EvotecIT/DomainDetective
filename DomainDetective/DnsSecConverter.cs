using System;
using System.Collections.Generic;
using DomainDetective.Protocols;

namespace DomainDetective {
    /// <summary>
    ///     Helper methods to convert <see cref="DnsSecAnalysis"/> results into
    ///     strongly typed objects.
    /// </summary>
    public static class DnsSecConverter {
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
            string algorithm = parts[1];
            if (int.TryParse(parts[1], out int algNum)) {
                string name = DNSKeyAnalysis.AlgorithmName(algNum);
                if (!string.IsNullOrEmpty(name)) {
                    algorithm = name;
                }
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
            string algorithm = parts[2];
            if (int.TryParse(parts[2], out int algNum)) {
                string name = DNSKeyAnalysis.AlgorithmName(algNum);
                if (!string.IsNullOrEmpty(name)) {
                    algorithm = name;
                }
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
    public class DsRecordInfo {
        /// <summary>Key tag value.</summary>
        public int KeyTag { get; set; }

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; }

        /// <summary>Digest type identifier.</summary>
        public int DigestType { get; set; }

        /// <summary>Digest hex string.</summary>
        public string Digest { get; set; }
    }

    /// <summary>
    ///     Simplified representation of a DNSKEY record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsKeyInfo {
        /// <summary>Record flags.</summary>
        public int Flags { get; set; }

        /// <summary>Protocol value.</summary>
        public byte Protocol { get; set; }

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; }

        /// <summary>Base64 encoded public key.</summary>
        public string PublicKey { get; set; }
    }

    /// <summary>
    ///     Simplified representation of an RRSIG record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class RrsigInfo {
        /// <summary>Key tag value.</summary>
        public int KeyTag { get; set; }

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; }

        /// <summary>Signature inception time.</summary>
        public DateTimeOffset Inception { get; set; }

        /// <summary>Signature expiration time.</summary>
        public DateTimeOffset Expiration { get; set; }

        /// <summary>Days remaining until the signature expires.</summary>
        public double DaysRemaining => (Expiration - DateTimeOffset.UtcNow).TotalDays;
    }
}
