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
        if (network == null) {
            throw new ArgumentNullException(nameof(network));
        }
        if (network.IsIPv4MappedToIPv6 && prefixLength >= 96) {
            network = network.MapToIPv4();
            prefixLength -= 96;
        }
        int bitCount = network.GetAddressBytes().Length * 8;
        if (prefixLength < 0 || prefixLength > bitCount) {
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        }
        Network = new IPAddress(ApplyMask(network.GetAddressBytes(), prefixLength));
        PrefixLength = prefixLength;
    }

    /// <summary>Checks if the range contains the specified address.</summary>
    public bool Contains(IPAddress address) {
        if (address == null) {
            throw new ArgumentNullException(nameof(address));
        }
        if (Network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
            address.IsIPv4MappedToIPv6) {
            address = address.MapToIPv4();
        }
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
    public static bool TryParse(string? text, out IpCidrRange range) {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var parts = text!.Trim().Split('/');
        if (parts.Length < 1 || parts.Length > 2)
            return false;
        if (!IPAddress.TryParse(parts[0].Trim(), out var addr) || addr == null)
            return false;
        int bitCount = addr.GetAddressBytes().Length * 8;
        int prefix = bitCount;
        if (parts.Length == 2 && !int.TryParse(parts[1].Trim(), out prefix))
            return false;
        if (prefix < 0 || prefix > bitCount)
            return false;
        try {
            range = new IpCidrRange(addr, prefix);
        } catch (ArgumentOutOfRangeException) {
            return false;
        }
        return true;
    }

    /// <summary>Parses a CIDR string or a single address.</summary>
    public static IpCidrRange Parse(string text) {
        if (!TryParse(text, out IpCidrRange range)) {
            throw new FormatException($"'{text}' is not a valid IPv4 or IPv6 CIDR prefix.");
        }
        return range;
    }

    /// <inheritdoc />
    public override string ToString() => Network + "/" + PrefixLength;

    private static byte[] ApplyMask(byte[] bytes, int prefixLength) {
        byte[] result = (byte[])bytes.Clone();
        int wholeBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        if (wholeBytes < result.Length && remainingBits > 0) {
            int mask = 0xFF << (8 - remainingBits);
            result[wholeBytes] = (byte)(result[wholeBytes] & mask);
            wholeBytes++;
        }
        for (int index = wholeBytes; index < result.Length; index++) {
            result[index] = 0;
        }
        return result;
    }
}
