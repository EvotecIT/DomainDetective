using System.Text.RegularExpressions;

namespace DomainDetective.Protocols {
    /// <summary>
    /// Provides helpers for DNSKEY record validation.
    /// </summary>
    internal static class DNSKeyAnalysis {
        /// <summary>
        /// Determines whether a string consists solely of hexadecimal characters.
        /// </summary>
        internal static bool IsHexadecimal(string input) {
            return Regex.IsMatch(input ?? string.Empty, @"\A[0-9a-fA-F]+\z");
        }
    }
}