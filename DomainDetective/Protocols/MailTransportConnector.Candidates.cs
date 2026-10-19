using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal static partial class MailTransportConnector {
    /// <summary>Races only pre-approved, family-filtered candidates and drains every losing connection.</summary>
    private static async Task<TcpClient> ConnectApprovedAsync(IPAddress[] addresses, int port, CancellationToken caller) {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(caller);
        using var admission = new SemaphoreSlim(Math.Min(4, addresses.Length));
        var winner = new TaskCompletionSource<TcpClient>(TaskCreationOptions.RunContinuationsAsynchronously);
        var errors = new ConcurrentQueue<Exception>();
        async Task TryAddressAsync(IPAddress address) {
            bool admitted = false;
            TcpClient? client = null;
            try {
                await admission.WaitAsync(lifetime.Token).ConfigureAwait(false);
                admitted = true;
                lifetime.Token.ThrowIfCancellationRequested();
                client = new TcpClient(address.AddressFamily);
                await AwaitConnectAsync(client, client.ConnectAsync(address, port), lifetime.Token).ConfigureAwait(false);
                if (winner.TrySetResult(client)) { client = null; }
            } catch (Exception error) when (error is not OutOfMemoryException) {
                errors.Enqueue(error);
            } finally {
                client?.Dispose();
                if (admitted) { admission.Release(); }
            }
        }
        var attempts = Task.WhenAll(addresses.Select(TryAddressAsync));
        try {
            await Task.WhenAny(winner.Task, attempts).ConfigureAwait(false);
            lifetime.Cancel();
            await attempts.ConfigureAwait(false);
            caller.ThrowIfCancellationRequested();
            if (winner.Task.Status == TaskStatus.RanToCompletion) { return await winner.Task.ConfigureAwait(false); }
            throw errors.LastOrDefault() ?? new SocketException((int)SocketError.HostUnreachable);
        } catch {
            lifetime.Cancel();
            try { await attempts.ConfigureAwait(false); } catch { }
            if (winner.Task.Status == TaskStatus.RanToCompletion) { (await winner.Task.ConfigureAwait(false)).Dispose(); }
            throw;
        }
    }
}
