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
            var nibbles = ipAddress
                .GetAddressBytes()
                .SelectMany(b => new[] { (b >> 4) & 0xF, b & 0xF })
                .Select(n => n.ToString("x"));
            return string.Join(".", nibbles.Reverse());
        }

        return string.Join(".", ipAddress.GetAddressBytes().Reverse());
    }
}