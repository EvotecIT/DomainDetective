using System;
using System.Net;
using System.Net.Sockets;

namespace DomainDetective.Network;

/// <summary>Describes the routing scope of an IP address.</summary>
public enum IpAddressVisibility
{
    /// <summary>The value could not be parsed or classified.</summary>
    Unknown = 0,
    /// <summary>Globally routable public address space.</summary>
    Public = 1,
    /// <summary>Private IPv4 address space.</summary>
    Private = 2,
    /// <summary>Local loopback address space.</summary>
    Loopback = 3,
    /// <summary>Link-local address space.</summary>
    LinkLocal = 4,
    /// <summary>Multicast address space.</summary>
    Multicast = 5,
    /// <summary>Address space reserved for documentation and examples.</summary>
    Documentation = 6,
    /// <summary>IPv6 unique-local address space.</summary>
    UniqueLocalV6 = 7,
    /// <summary>Carrier-grade NAT shared address space.</summary>
    Shared = 8,
    /// <summary>Reserved or otherwise non-routable address space.</summary>
    Reserved = 9
}

/// <summary>Classifies IPv4 and IPv6 addresses without performing network lookups.</summary>
public static class IpAddressClassifier
{
    /// <summary>Returns the stable inventory label for an address family.</summary>
    public static string GetAddressFamilyLabel(IPAddress? address)
    {
        if (address == null)
        {
            return string.Empty;
        }

        if (address.IsIPv4MappedToIPv6 || address.AddressFamily == AddressFamily.InterNetwork)
        {
            return "IPv4";
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return "IPv6";
        }
        return "Unknown";
    }

    /// <summary>Returns a stable inventory label from an address or a legacy family label.</summary>
    public static string GetAddressFamilyLabel(string? address, string? familyLabel = null)
    {
        if (IPAddress.TryParse((address ?? string.Empty).Trim(), out IPAddress? parsed) && parsed != null)
        {
            return GetAddressFamilyLabel(parsed);
        }

        string normalized = (familyLabel ?? string.Empty).Trim();
        if (string.Equals(normalized, "IPv4", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, AddressFamily.InterNetwork.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return "IPv4";
        }
        if (string.Equals(normalized, "IPv6", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, AddressFamily.InterNetworkV6.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return "IPv6";
        }
        return normalized.Length == 0 ? string.Empty : "Unknown";
    }

    /// <summary>Attempts to parse and classify an address.</summary>
    public static bool TryClassify(string? value, out IpAddressVisibility visibility)
    {
        visibility = IpAddressVisibility.Unknown;
        var trimmed = (value ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return false;
        }

        if (!IPAddress.TryParse(trimmed, out var ip) || ip == null)
        {
            return false;
        }

        visibility = Classify(ip);
        return true;
    }

    /// <summary>Classifies an address by routing scope.</summary>
    public static IpAddressVisibility Classify(IPAddress ip)
    {
        if (ip == null)
        {
            throw new System.ArgumentNullException(nameof(ip));
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (IPAddress.IsLoopback(ip))
        {
            return IpAddressVisibility.Loopback;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();

            if (b[0] == 10 || (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) || (b[0] == 192 && b[1] == 168))
            {
                return IpAddressVisibility.Private;
            }

            if (b[0] == 169 && b[1] == 254)
            {
                return IpAddressVisibility.LinkLocal;
            }

            if (b[0] >= 224 && b[0] <= 239)
            {
                return IpAddressVisibility.Multicast;
            }

            if ((b[0] == 192 && b[1] == 0 && b[2] == 2) ||
                (b[0] == 198 && b[1] == 51 && b[2] == 100) ||
                (b[0] == 203 && b[1] == 0 && b[2] == 113))
            {
                return IpAddressVisibility.Documentation;
            }

            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
            {
                return IpAddressVisibility.Shared;
            }

            if (b[0] == 0 || b[0] >= 240 || (b[0] == 198 && (b[1] == 18 || b[1] == 19)))
            {
                return IpAddressVisibility.Reserved;
            }

            return IpAddressVisibility.Public;
        }

        // IPv6
        if (ip.IsIPv6LinkLocal)
        {
            return IpAddressVisibility.LinkLocal;
        }

        if (ip.IsIPv6Multicast)
        {
            return IpAddressVisibility.Multicast;
        }

        // Unique local fc00::/7
        var bytes = ip.GetAddressBytes();
        if ((bytes[0] & 0xFE) == 0xFC)
        {
            return IpAddressVisibility.UniqueLocalV6;
        }

        // Documentation: 2001:db8::/32
        if (bytes.Length >= 4 && bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8)
        {
            return IpAddressVisibility.Documentation;
        }

        if (IPAddress.IPv6None.Equals(ip))
        {
            return IpAddressVisibility.Reserved;
        }

        return IpAddressVisibility.Public;
    }

    /// <summary>Returns true when the classification is not globally routable public space.</summary>
    public static bool IsNonPublic(IpAddressVisibility visibility)
    {
        return visibility == IpAddressVisibility.Private ||
               visibility == IpAddressVisibility.Loopback ||
               visibility == IpAddressVisibility.LinkLocal ||
               visibility == IpAddressVisibility.Multicast ||
               visibility == IpAddressVisibility.Documentation ||
               visibility == IpAddressVisibility.UniqueLocalV6 ||
               visibility == IpAddressVisibility.Shared ||
               visibility == IpAddressVisibility.Reserved;
    }
}
