using System.Collections.Generic;

namespace DomainDetective.PowerShell {
    internal static partial class OutputHelper {
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

    public class DnsSecInfo {
        public IReadOnlyList<string> DsRecords { get; set; }
        public IReadOnlyList<string> DnsKeys { get; set; }
        public IReadOnlyList<string> Signatures { get; set; }
        public bool AuthenticData { get; set; }
        public bool DsAuthenticData { get; set; }
        public bool DsMatch { get; set; }
        public bool ChainValid { get; set; }
    }
}
