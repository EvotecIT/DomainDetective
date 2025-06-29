using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestPortScanProgressOutput
{
    [Fact]
    public async Task WritesProgressLines()
    {
        var tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start();
        var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        var tcpAccept = tcpListener.AcceptTcpClientAsync();

        var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
        var udpTask = Task.Run(async () =>
        {
            var r = await udpServer.ReceiveAsync();
            await udpServer.SendAsync(r.Buffer, r.Buffer.Length, r.RemoteEndPoint);
        });

        var sw = new StringWriter();
        var original = Console.Out;
        Console.SetOut(sw);
        try
        {
            var logger = new InternalLogger { IsProgress = true };
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("127.0.0.1", new[] { tcpPort, udpPort }, logger);
            using var _ = await tcpAccept;
        }
        finally
        {
            Console.SetOut(original);
            tcpListener.Stop();
            udpServer.Close();
            await udpTask;
        }

        var output = sw.ToString();
        Assert.Contains("[progress]", output);
    }
}
