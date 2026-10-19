using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Establishes mail transport connections while preserving logical-host and address-family constraints.
/// </summary>
internal static partial class MailTransportConnector {
    internal static TimeSpan GetConnectTimeout(TimeSpan connectTimeout, TimeSpan operationTimeout) {
        if (connectTimeout == Timeout.InfiniteTimeSpan) { return operationTimeout; }
        if (operationTimeout == Timeout.InfiniteTimeSpan) { return connectTimeout; }
        return connectTimeout < operationTimeout ? connectTimeout : operationTimeout;
    }

    internal static async Task<TcpClient> ConnectAsync(
        MailTransportEndpoint endpoint,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? outboundAddressResolver,
        CancellationToken cancellationToken) {
        if (endpoint == null) {
            throw new ArgumentNullException(nameof(endpoint));
        }

        endpoint.Validate();
        cancellationToken.ThrowIfCancellationRequested();

        if (outboundAddressResolver == null &&
            endpoint.ConnectAddress == null &&
            endpoint.AddressFamily == MailTransportAddressFamily.Any &&
            IPAddress.TryParse(endpoint.HostName, out var literalAddress)) {
            literalAddress = NormalizeAddress(literalAddress);
            var client = new TcpClient(literalAddress.AddressFamily);
            await AwaitConnectAsync(client, client.ConnectAsync(literalAddress, endpoint.Port), cancellationToken).ConfigureAwait(false);
            return client;
        }

        IReadOnlyList<IPAddress> candidates;
        IPAddress? connectAddress = endpoint.ConnectAddress == null
            ? null
            : NormalizeAddress(endpoint.ConnectAddress);
        if (outboundAddressResolver != null) {
            var approved = await outboundAddressResolver(endpoint.HostName, cancellationToken).WaitWithCancellation(cancellationToken).ConfigureAwait(false)
                ?? Array.Empty<IPAddress>();
            IPAddress[] normalizedApproved = approved
                .Where(address => address != null)
                .Select(NormalizeAddress)
                .Distinct()
                .ToArray();
            if (connectAddress != null) {
                if (!normalizedApproved.Any(address => address.Equals(connectAddress))) {
                    throw new InvalidOperationException(
                        $"Connect address '{endpoint.ConnectAddress}' was not approved for logical host '{endpoint.HostName}'.");
                }
                candidates = new[] { connectAddress };
            } else {
                candidates = normalizedApproved;
            }
        } else if (connectAddress != null) {
            candidates = new[] { connectAddress };
        } else {
            // Hostname ConnectAsync also owns an OS DNS operation that socket
            // disposal cannot stop. Resolve first, then drain only IP connects.
#if NET8_0_OR_GREATER
            candidates = (await Dns.GetHostAddressesAsync(endpoint.HostName, cancellationToken)
                .ConfigureAwait(false)).Select(NormalizeAddress).ToArray();
#else
            candidates = (await Dns.GetHostAddressesAsync(endpoint.HostName)
                .WaitWithCancellation(cancellationToken)
                .ConfigureAwait(false))
                .Select(NormalizeAddress)
                .ToArray();
#endif
        }

        var filtered = candidates
            .Where(address => address != null && Matches(address, endpoint.AddressFamily))
            .Distinct()
            .ToArray();
        if (filtered.Length == 0) {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        return await ConnectApprovedAsync(filtered, endpoint.Port, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task AwaitConnectAsync(
        TcpClient client,
        Task connectTask,
        CancellationToken cancellationToken) {
        try {
            await connectTask.WaitWithCancellation(cancellationToken).ConfigureAwait(false);
        } catch {
            client.Dispose();
            // Callers supply IP-only connects: disposing terminates their owned native work. Observe
            // its completion rather than leaving a failed/canceled task behind.
            try { await connectTask.ConfigureAwait(false); } catch { }
            throw;
        }
    }

    internal static bool Matches(IPAddress address, MailTransportAddressFamily family) => family switch {
        MailTransportAddressFamily.Any => true,
        MailTransportAddressFamily.IPv4 => address.IsIPv4MappedToIPv6 || address.AddressFamily == AddressFamily.InterNetwork,
        MailTransportAddressFamily.IPv6 => !address.IsIPv4MappedToIPv6 && address.AddressFamily == AddressFamily.InterNetworkV6,
        _ => false
    };

    internal static MailTransportAddressFamily ToMailAddressFamily(IPAddress address) =>
        !address.IsIPv4MappedToIPv6 && address.AddressFamily == AddressFamily.InterNetworkV6
            ? MailTransportAddressFamily.IPv6
            : MailTransportAddressFamily.IPv4;

    private static IPAddress NormalizeAddress(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
