using System.Net;

namespace DomainDetective.Network;

internal enum IpAddressVisibility
{
    Unknown = 0,
    Public = 1,
    Private = 2,
    Loopback = 3,
    LinkLocal = 4,
    Multicast = 5,
    Documentation = 6,
    UniqueLocalV6 = 7
}

internal static class IpAddressClassifier
{
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

    public static IpAddressVisibility Classify(IPAddress ip)
    {
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

        return IpAddressVisibility.Public;
    }

    public static bool IsNonPublic(IpAddressVisibility visibility)
    {
        return visibility == IpAddressVisibility.Private ||
               visibility == IpAddressVisibility.Loopback ||
               visibility == IpAddressVisibility.LinkLocal ||
               visibility == IpAddressVisibility.Multicast ||
               visibility == IpAddressVisibility.Documentation ||
               visibility == IpAddressVisibility.UniqueLocalV6;
    }
}
