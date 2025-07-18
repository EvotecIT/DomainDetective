using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal static class DnsProbe
{
    private static readonly byte[] Query =
    {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    internal static async Task<bool> ProbeAsync(string host, int port, TimeSpan timeout, InternalLogger? logger, CancellationToken token)
    {
        try
        {
            using var udp = new UdpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);
#if NET8_0_OR_GREATER
            await udp.SendAsync(Query, host, port, cts.Token);
            var resp = await udp.ReceiveAsync(cts.Token);
#else
            await udp.SendAsync(Query, Query.Length, host, port).WaitWithCancellation(cts.Token);
            var resp = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
            return resp.Buffer.Length > 0;
        }
        catch (TaskCanceledException ex)
        {
            throw new OperationCanceledException(ex.Message, ex, token);
        }
        catch (Exception ex)
        {
            logger?.WriteVerbose("DNS query failed for {0}:{1} - {2}", host, port, ex.Message);
            return false;
        }
    }
}
