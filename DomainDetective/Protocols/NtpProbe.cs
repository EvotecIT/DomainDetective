using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal static class NtpProbe
{
    internal static async Task<bool> ProbeAsync(string host, int port, TimeSpan timeout, InternalLogger? logger, CancellationToken token)
    {
        try
        {
            using var udp = new UdpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);
            var request = new byte[48];
            request[0] = 0x1B;
#if NET8_0_OR_GREATER
            await udp.SendAsync(request, host, port, cts.Token);
            var resp = await udp.ReceiveAsync(cts.Token);
#else
            await udp.SendAsync(request, request.Length, host, port).WaitWithCancellation(cts.Token);
            var resp = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
            return resp.Buffer.Length >= 48;
        }
        catch (TaskCanceledException ex)
        {
            throw new OperationCanceledException(ex.Message, ex, token);
        }
        catch (Exception ex)
        {
            logger?.WriteVerbose("NTP query failed for {0}:{1} - {2}", host, port, ex.Message);
            return false;
        }
    }
}
