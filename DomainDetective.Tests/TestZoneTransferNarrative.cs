using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestZoneTransferNarrative
{
    private static byte[] BuildError(ushort id)
    {
        byte[] zone = { 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0 };
        var msg = new byte[12 + zone.Length + 4];
        msg[0] = (byte)(id >> 8);
        msg[1] = (byte)id;
        msg[2] = 0x84;
        msg[3] = 5;
        msg[5] = 1;
        Buffer.BlockCopy(zone, 0, msg, 12, zone.Length);
        int offset = 12 + zone.Length;
        msg[offset] = 0;
        msg[offset + 1] = 0xFC;
        msg[offset + 2] = 0;
        msg[offset + 3] = 1;
        var resp = new byte[msg.Length + 2];
        resp[0] = (byte)(msg.Length >> 8);
        resp[1] = (byte)(msg.Length & 0xFF);
        Buffer.BlockCopy(msg, 0, resp, 2, msg.Length);
        return resp;
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            var read = await stream.ReadAsync(buffer, offset, count);
            if (read == 0)
            {
                throw new System.IO.EndOfStreamException();
            }

            offset += read;
            count -= read;
        }
    }

    [Fact]
    public async Task BuildsNarrativeAndPositiveAdvice()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var buffer = new byte[512];
            await ReadExactlyAsync(stream, buffer, 0, 2);
            int len = buffer[0] << 8 | buffer[1];
            if (len > 0) { await ReadExactlyAsync(stream, buffer, 0, len); }
            ushort id = (ushort)((buffer[0] << 8) | buffer[1]);
            var resp = BuildError(id);
            await stream.WriteAsync(resp, 0, resp.Length);
        });

        try
        {
            var logger = new InternalLogger();
            var analysis = new ZoneTransferAnalysis();
            await analysis.AnalyzeServers("example.com", new[] { "localhost:" + port }, logger);
            var narrative = ZoneTransferNarrative.Build(analysis, logger: logger);
            Assert.Contains("All tested servers refused AXFR.", narrative.Highlights);
            var positives = RecommendationEngine.FromPositives(analysis.Assessments);
            Assert.Contains(positives, p => p.Code == ZoneTransferCodes.Restricted);
        }
        finally
        {
            listener.Stop();
            await serverTask;
        }
    }
}
