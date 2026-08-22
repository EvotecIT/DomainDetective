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
internal static class MailTransportConnector {
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
            endpoint.AddressFamily == MailTransportAddressFamily.Any) {
            var isAddressLiteral = IPAddress.TryParse(endpoint.HostName, out var literalAddress);
            var client = isAddressLiteral
                ? new TcpClient(literalAddress!.AddressFamily)
                : new TcpClient();
            if (isAddressLiteral) {
                await AwaitConnectAsync(
                    client,
                    client.ConnectAsync(literalAddress!, endpoint.Port),
                    cancellationToken).ConfigureAwait(false);
            } else {
                await AwaitConnectAsync(
                    client,
                    client.ConnectAsync(endpoint.HostName, endpoint.Port),
                    cancellationToken).ConfigureAwait(false);
            }
            return client;
        }

        IReadOnlyList<IPAddress> candidates;
        if (outboundAddressResolver != null) {
            var approved = await outboundAddressResolver(endpoint.HostName, cancellationToken).ConfigureAwait(false)
                ?? Array.Empty<IPAddress>();
            if (endpoint.ConnectAddress != null) {
                if (!approved.Any(address => address.Equals(endpoint.ConnectAddress))) {
                    throw new InvalidOperationException(
                        $"Connect address '{endpoint.ConnectAddress}' was not approved for logical host '{endpoint.HostName}'.");
                }
                candidates = new[] { endpoint.ConnectAddress };
            } else {
                candidates = approved;
            }
        } else if (endpoint.ConnectAddress != null) {
            candidates = new[] { endpoint.ConnectAddress };
        } else {
            candidates = await Dns.GetHostAddressesAsync(endpoint.HostName)
                .WaitWithCancellation(cancellationToken)
                .ConfigureAwait(false);
        }

        var filtered = candidates
            .Where(address => address != null && Matches(address, endpoint.AddressFamily))
            .Distinct()
            .ToArray();
        if (filtered.Length == 0) {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        Exception? lastError = null;
        foreach (var address in filtered) {
            cancellationToken.ThrowIfCancellationRequested();
            var client = new TcpClient(address.AddressFamily);
            try {
                await AwaitConnectAsync(
                    client,
                    client.ConnectAsync(address, endpoint.Port),
                    cancellationToken).ConfigureAwait(false);
                return client;
            } catch (Exception ex) when (ex is not OperationCanceledException) {
                lastError = ex;
            }
        }

        if (lastError != null) {
            throw lastError;
        }
        throw new SocketException((int)SocketError.HostUnreachable);
    }

    internal static async Task AwaitConnectAsync(
        TcpClient client,
        Task connectTask,
        CancellationToken cancellationToken) {
        try {
            await connectTask.WaitWithCancellation(cancellationToken).ConfigureAwait(false);
        } catch {
            client.Dispose();
            throw;
        }
    }

    internal static bool Matches(IPAddress address, MailTransportAddressFamily family) => family switch {
        MailTransportAddressFamily.Any => true,
        MailTransportAddressFamily.IPv4 => address.AddressFamily == AddressFamily.InterNetwork,
        MailTransportAddressFamily.IPv6 => address.AddressFamily == AddressFamily.InterNetworkV6,
        _ => false
    };

    internal static MailTransportAddressFamily ToMailAddressFamily(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6
            ? MailTransportAddressFamily.IPv6
            : MailTransportAddressFamily.IPv4;
}
