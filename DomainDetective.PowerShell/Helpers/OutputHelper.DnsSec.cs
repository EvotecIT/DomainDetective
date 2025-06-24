using DomainDetective;

namespace DomainDetective.PowerShell {
    /// <summary>
    ///     Helper methods for DNSSEC analysis output.
    /// </summary>
    internal static partial class OutputHelper {
        /// <summary>
        ///     Creates a summary information object from the analysis results.
        /// </summary>
        /// <param name="analysis">Analysis instance.</param>
        /// <returns>Structured DNSSEC information.</returns>
        public static DnsSecInfo Convert(DNSSecAnalysis analysis) {
            return DnsSecConverter.Convert(analysis);
        }
    }
}