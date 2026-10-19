using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestPortScanProgressOutput
{
    [Fact]
    public async Task WritesProgressLines()
    {
        var tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start();
        var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        var tcpAccept = tcpListener.AcceptTcpClientAsync();

        var sw = new StringWriter();
        var original = Console.Out;
        Console.SetOut(sw);
        try
        {
            var logger = new InternalLogger { IsProgress = true };
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("127.0.0.1", new[] { tcpPort }, logger);
            using var _ = await tcpAccept;
        }
        finally
        {
            Console.SetOut(original);
            tcpListener.Stop();
        }

        var output = sw.ToString();
        Assert.Contains("[progress]", output);
    }
}
