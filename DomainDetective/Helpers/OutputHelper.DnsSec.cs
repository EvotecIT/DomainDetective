using System.Collections.Generic;

namespace DomainDetective {
    /// <summary>
    ///     Converts DNSSEC analysis results into simple objects.
    /// </summary>
    public static partial class OutputHelper {
        /// <summary>
        ///     Creates a summary information object from the analysis results.
        /// </summary>
        /// <param name="analysis">Analysis instance.</param>
        /// <returns>Structured DNSSEC information.</returns>
        public static DnsSecInfo Convert(DNSSecAnalysis analysis) {
            return new DnsSecInfo {
                DsRecords = analysis.DsRecords,
                DnsKeys = analysis.DnsKeys,
                Signatures = analysis.Signatures,
                AuthenticData = analysis.AuthenticData,
                DsAuthenticData = analysis.DsAuthenticData,
                DsMatch = analysis.DsMatch,
                ChainValid = analysis.ChainValid
            };
        }
    }

    /// <summary>
    ///     DNSSEC validation results in a simplified form.
    /// </summary>
    public class DnsSecInfo {
        /// <summary>Returned DS records.</summary>
        public IReadOnlyList<string> DsRecords { get; set; }
        /// <summary>Returned DNSKEY records.</summary>
        public IReadOnlyList<string> DnsKeys { get; set; }
        /// <summary>DNSSEC signature records.</summary>
        public IReadOnlyList<string> Signatures { get; set; }
        /// <summary>True when the DNSKEY query had the AD flag set.</summary>
        public bool AuthenticData { get; set; }
        /// <summary>True when the DS query had the AD flag set.</summary>
        public bool DsAuthenticData { get; set; }
        /// <summary>Indicates whether the DS record matches the DNSKEY.</summary>
        public bool DsMatch { get; set; }
        /// <summary>True when the entire DNSSEC chain validated.</summary>
        public bool ChainValid { get; set; }
    }
}
