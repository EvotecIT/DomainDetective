using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace DomainDetective;

/// <summary>
/// Helper extensions for working with <see cref="IPAddress"/> instances.
/// </summary>
public static class IPAddressExtensions {
    /// <summary>
    /// Converts an <see cref="IPAddress"/> to its PTR format.
    /// </summary>
    /// <param name="ipAddress">The IP address to convert.</param>
    /// <returns>The reversed nibble or byte representation suitable for PTR queries.</returns>
    public static string ToPtrFormat(this IPAddress ipAddress) {
        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6) {
            var bytes = ipAddress.GetAddressBytes();
            var result = new char[bytes.Length * 4 - 1];
            var pos = 0;
            for (int i = bytes.Length - 1; i >= 0; i--) {
                var b = bytes[i];
                result[pos++] = GetHex(b & 0xF);
                result[pos++] = '.';
                result[pos++] = GetHex(b >> 4);
                if (i != 0) {
                    result[pos++] = '.';
                }
            }

            return new string(result, 0, pos);
        }

        return string.Join(".", ipAddress.GetAddressBytes().Reverse());
    }

    /// <summary>
    /// Returns a string representing the network prefix for grouping.
    /// </summary>
    /// <param name="ipAddress">The IP address.</param>
    /// <returns>
    /// The /24 prefix for IPv4 or /48 prefix for IPv6 formatted as a string.
    /// </returns>
    public static string GetSubnetKey(this IPAddress ipAddress) {
        var bytes = ipAddress.GetAddressBytes();
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork) {
            return $"{bytes[0]}.{bytes[1]}.{bytes[2]}";
        }

        // IPv6 uses first 48 bits (six bytes)
        return string.Join(":",
            Enumerable.Range(0, 3)
                .Select(i => $"{bytes[i * 2]:x2}{bytes[i * 2 + 1]:x2}"));
    }

    private static char GetHex(int value) {
        const string hex = "0123456789abcdef";
        return hex[value & 0xF];
    }
}