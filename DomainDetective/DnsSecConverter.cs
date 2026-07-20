using System;
using System.Collections.Generic;
using DomainDetective.Protocols;

namespace DomainDetective {
    /// <summary>
    ///     Helper methods to convert <see cref="DnsSecAnalysis"/> results into
    ///     strongly typed objects.
    /// </summary>
    public static class DnsSecConverter {
        private static string MapAlgorithmNumber(int number) {
            return number switch {
                8 => "RSASHA256",
                13 => "ECDSAP256SHA256",
                14 => "ECDSAP384SHA384",
                _ => DNSKeyAnalysis.AlgorithmName(number) ?? string.Empty,
            };
        }

        private static DnsDigestType MapDigestTypeNumber(int number) {
            return number switch {
                1 => DnsDigestType.Sha1,
                2 => DnsDigestType.Sha256,
                4 => DnsDigestType.Sha384,
                _ => DnsDigestType.Unknown,
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
                ValidationStatus = analysis.ValidationStatus,
                SubjectAuthenticData = analysis.SubjectAuthenticData,
                ValidatedZone = analysis.ValidatedZone ?? string.Empty,
                ValidationMethod = analysis.ValidationMethod,
                DsTtls = analysis.DsTtls,
                RootKeyTag = analysis.RootKeyTag,
                RootAnchorExpiration = analysis.RootAnchorExpiration,
                KeyExpiresSoon = analysis.KeyExpiresSoon,
                MismatchSummary = analysis.MismatchSummary,
                Warnings = analysis.Warnings,
                UsedLocalValidation = analysis.UsedLocalValidation,
                Assessments = analysis.Assessments
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
            _ = int.TryParse(parts[2], out int digestTypeNumber);
            string algorithm = parts[1];
            if (int.TryParse(parts[1], out int algNum)) {
                string name = MapAlgorithmNumber(algNum);
                if (!string.IsNullOrEmpty(name)) {
                    algorithm = name;
                }
            }
            return new DsRecordInfo {
                KeyTag = keyTag,
                Algorithm = algorithm,
                DigestType = MapDigestTypeNumber(digestTypeNumber),
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
                string name = MapAlgorithmNumber(algNum);
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
    /// <remarks>
    /// The class aggregates DS, DNSKEY and RRSIG information for easy
    /// consumption by tools that don't require full record details.
    /// </remarks>
    public class DnsSecInfo {
        /// <summary>Returned DS records.</summary>
        public IReadOnlyList<DsRecordInfo> DsRecords { get; set; } = Array.Empty<DsRecordInfo>();

        /// <summary>Returned DNSKEY records.</summary>
        public IReadOnlyList<DnsKeyInfo> DnsKeys { get; set; } = Array.Empty<DnsKeyInfo>();

        /// <summary>DNSSEC signature records.</summary>
        public IReadOnlyList<string> Signatures { get; set; } = Array.Empty<string>();

        /// <summary>Structured RRSIG records.</summary>
        public IReadOnlyList<RrsigInfo> Rrsigs { get; set; } = Array.Empty<RrsigInfo>();

        /// <summary>True when the DNSKEY query had the AD flag set.</summary>
        public bool AuthenticData { get; set; }

        /// <summary>True when the DS query had the AD flag set.</summary>
        public bool DsAuthenticData { get; set; }

        /// <summary>Indicates whether the DS record matches the DNSKEY.</summary>
        public bool DsMatch { get; set; }

        /// <summary>True when the entire DNSSEC chain validated.</summary>
        public bool ChainValid { get; set; }

        /// <summary>Evidence-backed state for the requested DNS name.</summary>
        public DnssecValidationStatus ValidationStatus { get; set; }

        /// <summary>True when the requested subject response carried authenticated-data evidence.</summary>
        public bool SubjectAuthenticData { get; set; }

        /// <summary>Closest enclosing signed zone evaluated for the subject.</summary>
        public string ValidatedZone { get; set; } = string.Empty;

        /// <summary>Evidence method used to classify the result.</summary>
        public string ValidationMethod { get; set; } = string.Empty;

        /// <summary>TTL values for each DS lookup in the validation chain.</summary>
        public IReadOnlyList<int> DsTtls { get; set; } = Array.Empty<int>();

        /// <summary>Key tag for the root trust anchor.</summary>
        public int RootKeyTag { get; set; }

        /// <summary>Expiration time of the root trust anchor if known.</summary>
        public DateTimeOffset? RootAnchorExpiration { get; set; }

        /// <summary>True when the validator detected keys or signatures expiring soon.</summary>
        public bool KeyExpiresSoon { get; set; }

        /// <summary>Descriptions of any mismatches encountered.</summary>
        public IReadOnlyList<string> MismatchSummary { get; set; } = Array.Empty<string>();

        /// <summary>Human-readable warnings produced during validation.</summary>
        public IReadOnlyList<string> Warnings { get; set; } = Array.Empty<string>();

        /// <summary>True when local DNSSEC validation was enabled for the run.</summary>
        public bool UsedLocalValidation { get; set; }

        /// <summary>Structured assessments gathered during DNSSEC validation.</summary>
        public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    }

    /// <summary>
    ///     Simplified representation of a DS record.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Information is derived from standard DNS record text.</remarks>
    public class DsRecordInfo {
        /// <summary>Key tag value.</summary>
        public int KeyTag { get; set; }

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>Digest type identifier.</summary>
        public DnsDigestType DigestType { get; set; }

        /// <summary>Digest hex string.</summary>
        public string Digest { get; set; } = string.Empty;
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

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>Base64 encoded public key.</summary>
        public string PublicKey { get; set; } = string.Empty;
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

        /// <summary>Algorithm name.</summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>Signature inception time.</summary>
        public DateTimeOffset Inception { get; set; }

        /// <summary>Signature expiration time.</summary>
        public DateTimeOffset Expiration { get; set; }

        /// <summary>Days remaining until the signature expires.</summary>
        public double DaysRemaining => (Expiration - DateTimeOffset.UtcNow).TotalDays;
    }
}
