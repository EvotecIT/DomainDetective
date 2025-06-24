using System.Text.RegularExpressions;

namespace DomainDetective.Protocols {
    internal static class DNSKeyAnalysis {
        internal static bool IsHexadecimal(string input) {
            return Regex.IsMatch(input ?? string.Empty, @"\A[0-9a-fA-F]+\z");
        }
    }
}