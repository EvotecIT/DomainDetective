using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestOpenRelayNarrative
{
    [Fact]
    public async Task OpenRelayNarrativeShowsDeniedAndPositive()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream);
            using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("220-test");
            await writer.WriteLineAsync("220 local ESMTP");
            await reader.ReadLineAsync();
            await writer.WriteLineAsync("250-hello");
            await writer.WriteLineAsync("250 hello");
            await reader.ReadLineAsync();
            await writer.WriteLineAsync("250-OK");
            await writer.WriteLineAsync("250 OK");
            await reader.ReadLineAsync();
            await writer.WriteLineAsync("550 relay denied");
            await reader.ReadLineAsync();
            await writer.WriteLineAsync("221 bye");
        });

        try
        {
            var logger = new InternalLogger();
            var analysis = new OpenRelayAnalysis();
            await analysis.AnalyzeServer("localhost", port, logger);
            var narrative = OpenRelayNarrative.Build(analysis, logger);
            Assert.Contains("No servers allowed unauthenticated relay.", narrative.Highlights);
            var positives = RecommendationEngine.FromPositives(analysis.Assessments);
            Assert.Contains(positives, p => p.Code == OpenRelayCodes.Denied);
        }
        finally
        {
            listener.Stop();
            await serverTask;
        }
    }
}
