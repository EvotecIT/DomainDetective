using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DomainDetective.Protocols {
    /// <summary>
    /// Provides helpers for DNSKEY record validation.
    /// </summary>
    internal static class DNSKeyAnalysis {
        private static readonly HashSet<int> ValidAlgorithms = new() {
            1, 2, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 23, 252, 253, 254,
        };
        /// <summary>
        /// Determines whether a string consists solely of hexadecimal characters.
        /// </summary>
        internal static bool IsHexadecimal(string input) {
            return Regex.IsMatch(input ?? string.Empty, @"\A[0-9a-fA-F]+\z");
        }

        internal static bool IsValidAlgorithmNumber(int number) {
            return ValidAlgorithms.Contains(number);
        }
    }
}