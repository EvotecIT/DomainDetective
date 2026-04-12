using System;
using System.Net;

namespace DomainDetective;

/// <summary>
/// Represents an IP network in CIDR notation.
/// </summary>
public readonly struct IpCidrRange {
    /// <summary>Base network address.</summary>
    public IPAddress Network { get; }
    /// <summary>Prefix length.</summary>
    public int PrefixLength { get; }

    /// <summary>Initializes a new instance of the IpCidrRange class.</summary>
    public IpCidrRange(IPAddress network, int prefixLength) {
        Network = network;
        PrefixLength = prefixLength;
    }

    /// <summary>Checks if the range contains the specified address.</summary>
    public bool Contains(IPAddress address) {
        if (address.AddressFamily != Network.AddressFamily)
            return false;
        var addressBytes = address.GetAddressBytes();
        var networkBytes = Network.GetAddressBytes();
        var fullBytes = PrefixLength / 8;
        var remainingBits = PrefixLength % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (addressBytes[i] != networkBytes[i])
                return false;
        }
        if (remainingBits == 0)
            return true;
        int mask = 0xFF << (8 - remainingBits);
        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    /// <summary>Parses a CIDR string.</summary>
    public static bool TryParse(string text, out IpCidrRange range) {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var parts = text.Split('/');
        if (parts.Length != 2)
            return false;
        if (!IPAddress.TryParse(parts[0], out var addr))
            return false;
        if (!int.TryParse(parts[1], out var prefix))
            return false;
        range = new IpCidrRange(addr, prefix);
        return true;
    }
}
