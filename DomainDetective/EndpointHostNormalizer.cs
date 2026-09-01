using System;
using System.Net;

namespace DomainDetective;

/// <summary>Normalizes logical endpoint hosts for protocol, DNS, and inventory use.</summary>
internal static class EndpointHostNormalizer {
    public static string Normalize(string? value, bool lowercase = false) {
        string normalized = (value ?? string.Empty).Trim().TrimEnd('.');
        if (normalized.Length >= 2 && normalized[0] == '[' && normalized[normalized.Length - 1] == ']') {
            normalized = normalized.Substring(1, normalized.Length - 2);
        }
        return lowercase ? normalized.ToLowerInvariant() : normalized;
    }

    public static string FormatForUriAuthority(string? value) {
        string normalized = Normalize(value);
        return IPAddress.TryParse(normalized, out IPAddress? address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{normalized}]"
            : normalized;
    }
}
