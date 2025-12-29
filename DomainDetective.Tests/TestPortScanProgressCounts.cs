using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestPortScanProgressCounts {
    [Fact]
    public async Task ReportsEventsPerPort() {
        var tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start();
        var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        var tcpAccept = tcpListener.AcceptTcpClientAsync();

        using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
        var udpTask = Task.Run(async () => {
            var r = await udpServer.ReceiveAsync();
            await udpServer.SendAsync(r.Buffer, r.Buffer.Length, r.RemoteEndPoint);
        });

        var events = new List<LogEventArgs>();
        var logger = new InternalLogger();
        logger.OnProgressMessage += (_, e) => events.Add(e);

        var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
        await analysis.Scan("127.0.0.1", new[] { tcpPort, udpPort }, logger);
        using var _ = await tcpAccept;

        tcpListener.Stop();
        await udpTask;

        var portEvents = events.Where(e => e.ProgressActivity == "PortScan").ToList();
        Assert.Equal(2, portEvents.Count);
        Assert.Equal(100, portEvents.Last().ProgressPercentage);
    }
}
