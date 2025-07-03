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

        private static readonly HashSet<int> DeprecatedAlgorithms = new() {
            1, 3, 5, 6, 7, 12,
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

        internal static bool IsDeprecatedAlgorithmNumber(int number) {
            return DeprecatedAlgorithms.Contains(number);
        }

        internal static string AlgorithmName(int number) {
            return number switch {
                1 => "RSAMD5",
                2 => "DH",
                3 => "DSA",
                4 => "ECC",
                5 => "RSASHA1",
                6 => "DSANSEC3SHA1",
                7 => "RSASHA1NSEC3SHA1",
                8 => "RSASHA256",
                9 => "RESERVED",
                10 => "RSASHA512",
                11 => "RESERVED",
                12 => "ECCGOST",
                13 => "ECDSAP256SHA256",
                14 => "ECDSAP384SHA384",
                15 => "ED25519",
                16 => "ED448",
                17 => "SM2SM3",
                23 => "ECC-GOST12",
                252 => "INDIRECT",
                253 => "PRIVATEDNS",
                254 => "PRIVATEOID",
                _ => string.Empty,
            };
        }
    }
}