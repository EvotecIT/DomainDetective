using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Security;

/// <summary>Result of resolving and classifying an outbound network target.</summary>
public sealed class PublicNetworkTargetValidationResult {
    /// <summary>True when the host resolved and every returned address is publicly routable.</summary>
    public bool IsAllowed { get; internal set; }
    /// <summary>Reason the target was rejected.</summary>
    public string? Error { get; internal set; }
    /// <summary>Addresses returned by the resolver.</summary>
    public IReadOnlyList<IPAddress> Addresses { get; internal set; } = Array.Empty<IPAddress>();
}

/// <summary>Resolves outbound host names and rejects private, local, documentation, multicast, and otherwise special-use addresses.</summary>
public sealed class PublicNetworkTargetValidator {
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolver;

    /// <summary>Creates a validator using the operating system DNS resolver.</summary>
    public PublicNetworkTargetValidator() : this(ResolveAsync) { }

    /// <summary>Creates a validator with an explicit resolver.</summary>
    public PublicNetworkTargetValidator(Func<string, CancellationToken, Task<IPAddress[]>> resolver) {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
    }

    /// <summary>Resolves and validates a host before an outbound connection is attempted.</summary>
    public async Task<PublicNetworkTargetValidationResult> ValidateAsync(string host, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(host)) {
            return Rejected("The target host is empty.");
        }

        IPAddress[] addresses;
        try {
            addresses = IPAddress.TryParse(host, out var literal)
                ? new[] { literal }
                : await _resolver(host.TrimEnd('.'), cancellationToken).ConfigureAwait(false);
        } catch (OperationCanceledException) {
            throw;
        } catch (Exception ex) {
            return Rejected($"The target host could not be resolved: {ex.Message}");
        }

        var distinct = addresses.Where(static address => address != null).Distinct().ToArray();
        if (distinct.Length == 0) {
            return Rejected("The target host did not resolve to an address.");
        }

        var blocked = distinct.FirstOrDefault(static address => !IsPublicAddress(address));
        if (blocked != null) {
            return new PublicNetworkTargetValidationResult {
                IsAllowed = false,
                Error = $"The target resolves to a non-public or special-use address ({blocked}).",
                Addresses = distinct
            };
        }

        return new PublicNetworkTargetValidationResult { IsAllowed = true, Addresses = distinct };
    }

    /// <summary>Returns true only for addresses that are not in known non-public or special-use ranges.</summary>
    public static bool IsPublicAddress(IPAddress address) {
        if (address == null) return false;
        if (address.IsIPv4MappedToIPv6) return IsPublicAddress(address.MapToIPv4());

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork) {
            var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            return !InRange(value, 0x00000000, 8) &&
                   !InRange(value, 0x0A000000, 8) &&
                   !InRange(value, 0x64400000, 10) &&
                   !InRange(value, 0x7F000000, 8) &&
                   !InRange(value, 0xA9FE0000, 16) &&
                   !InRange(value, 0xAC100000, 12) &&
                   !InRange(value, 0xC0000000, 24) &&
                   !InRange(value, 0xC0000200, 24) &&
                   !InRange(value, 0xC0A80000, 16) &&
                   !InRange(value, 0xC6120000, 15) &&
                   !InRange(value, 0xC6336400, 24) &&
                   !InRange(value, 0xCB007100, 24) &&
                   !InRange(value, 0xE0000000, 4) &&
                   !InRange(value, 0xF0000000, 4);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6 ||
            address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6Loopback) ||
            address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal) {
            return false;
        }

        return !HasPrefix(bytes, new byte[] { 0xFC }, 7) &&
               !HasPrefix(bytes, new byte[] { 0xFE, 0x80 }, 10) &&
               !HasPrefix(bytes, new byte[] { 0xFF }, 8) &&
               !HasPrefix(bytes, new byte[] { 0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0 }, 96) &&
               !HasPrefix(bytes, new byte[] { 0x00, 0x64, 0xFF, 0x9B, 0x00, 0x01 }, 48) &&
               !HasPrefix(bytes, new byte[] { 0x01, 0x00, 0, 0, 0, 0, 0, 0 }, 64) &&
               !HasPrefix(bytes, new byte[] { 0x20, 0x01, 0x00, 0x00 }, 32) &&
               !HasPrefix(bytes, new byte[] { 0x20, 0x02 }, 16) &&
               !HasPrefix(bytes, new byte[] { 0x20, 0x01, 0x0D, 0xB8 }, 32);
    }

    private static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) {
        return await Dns.GetHostAddressesAsync(host).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
    }

    private static bool InRange(uint value, uint network, int prefixLength) {
        var mask = prefixLength == 0 ? 0U : uint.MaxValue << (32 - prefixLength);
        return (value & mask) == (network & mask);
    }

    private static bool HasPrefix(byte[] address, byte[] prefix, int prefixLength) {
        for (var bit = 0; bit < prefixLength; bit++) {
            var mask = 1 << (7 - (bit % 8));
            if ((address[bit / 8] & mask) != (prefix[bit / 8] & mask)) return false;
        }
        return true;
    }

    private static PublicNetworkTargetValidationResult Rejected(string error) => new() { Error = error };
}
