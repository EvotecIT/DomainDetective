using System;
using System.Net;

namespace DomainDetective;

/// <summary>Normalizes logical endpoint hosts for protocol, DNS, and inventory use.</summary>
internal static class EndpointHostNormalizer {
    /// <summary>Formats a URI host with IPv6 brackets while retaining its interface scope.</summary>
    internal static string FormatUriHost(Uri uri) => uri.HostNameType == UriHostNameType.IPv6
        ? $"[{uri.IdnHost}]" : uri.IdnHost;

    /// <summary>Formats an authority without dropping an IPv6 scope or a non-default port.</summary>
    internal static string FormatUriAuthority(Uri uri) => FormatUriHost(uri) +
        (uri.IsDefaultPort ? string.Empty : $":{uri.Port}");

    /// <summary>Changes a port without losing the scope that Uri.Host and UriBuilder otherwise omit.</summary>
    internal static Uri WithPort(Uri uri, int port) => new UriBuilder(uri) { Host = uri.IdnHost, Port = port }.Uri;

    /// <summary>Serializes a URI including its scoped IPv6 endpoint identity.</summary>
    internal static string FormatUri(Uri uri, bool includeDefaultPort = false) {
        if (!includeDefaultPort || !uri.IsDefaultPort) {
            return uri.GetComponents(UriComponents.SerializationInfoString, UriFormat.UriEscaped);
        }
        string userInfo = string.IsNullOrEmpty(uri.UserInfo) ? string.Empty : uri.UserInfo + "@";
        string host = uri.HostNameType == UriHostNameType.IPv6
            ? FormatUriHost(uri) : uri.GetComponents(UriComponents.Host, UriFormat.UriEscaped);
        return $"{uri.Scheme}://{userInfo}{host}:{uri.Port}{uri.PathAndQuery}{uri.Fragment}";
    }

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
