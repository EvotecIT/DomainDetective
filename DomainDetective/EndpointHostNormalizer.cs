using System;
using System.Net;

namespace DomainDetective;

/// <summary>Normalizes logical endpoint hosts for protocol, DNS, and inventory use.</summary>
internal static class EndpointHostNormalizer {
    public static string Normalize(string? value, bool lowercase = false) {
        TryNormalize(value, out string normalized, lowercase);
        return normalized;
    }

    public static bool TryNormalize(string? value, out string normalized, bool lowercase = false) {
        normalized = (value ?? string.Empty).Trim().TrimEnd('.');
        bool containsOpeningBracket = normalized.IndexOf('[') >= 0;
        bool containsClosingBracket = normalized.IndexOf(']') >= 0;
        if (containsOpeningBracket || containsClosingBracket) {
            if (normalized.Length < 2 ||
                normalized[0] != '[' ||
                normalized[normalized.Length - 1] != ']') {
                normalized = lowercase ? normalized.ToLowerInvariant() : normalized;
                return false;
            }

            string candidate = normalized.Substring(1, normalized.Length - 2);
            if (!IPAddress.TryParse(candidate, out IPAddress? address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) {
                normalized = lowercase ? normalized.ToLowerInvariant() : normalized;
                return false;
            }
            normalized = address.ToString();
        }

        if (IPAddress.TryParse(normalized, out IPAddress? literalAddress) && literalAddress != null) {
            if (literalAddress.IsIPv4MappedToIPv6) {
                literalAddress = literalAddress.MapToIPv4();
            }
            normalized = literalAddress.ToString();
        }
        normalized = lowercase ? normalized.ToLowerInvariant() : normalized;
        return true;
    }

    public static string FormatForUriAuthority(string? value) {
        string normalized = Normalize(value);
        return IPAddress.TryParse(normalized, out IPAddress? address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{normalized}]"
            : normalized;
    }
}
