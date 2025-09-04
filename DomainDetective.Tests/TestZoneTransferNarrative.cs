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
        var header = new byte[12];
        header[0] = (byte)(id >> 8);
        header[1] = (byte)(id & 0xFF);
        header[2] = 0x80;
        header[3] = 5;
        header[5] = 0x01;
        var msg = new byte[18];
        Buffer.BlockCopy(header, 0, msg, 0, 12);
        msg[12] = 0;
        msg[13] = 0;
        msg[14] = 0xFC;
        msg[15] = 0;
        msg[16] = 0x01;
        var resp = new byte[msg.Length + 2];
        resp[0] = (byte)(msg.Length >> 8);
        resp[1] = (byte)(msg.Length & 0xFF);
        Buffer.BlockCopy(msg, 0, resp, 2, msg.Length);
        return resp;
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
            await stream.ReadAsync(buffer, 0, 2);
            int len = buffer[0] << 8 | buffer[1];
            if (len > 0) { await stream.ReadAsync(buffer, 0, len); }
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
