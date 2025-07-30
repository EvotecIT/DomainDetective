using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDomainHealthCheckProgress {
    [Fact]
    public async Task CollectsProgressEvents() {
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

        var healthCheck = new DomainHealthCheck();
        healthCheck.PortScanAnalysis.Timeout = TimeSpan.FromMilliseconds(200);
        await healthCheck.ScanPorts("127.0.0.1", new[] { tcpPort, udpPort });
        using var _ = await tcpAccept;

        tcpListener.Stop();
        await udpTask;

        var events = healthCheck.GetProgressEvents()
            .Where(e => e.ProgressActivity == "PortScan")
            .ToList();
        Assert.Equal(2, events.Count);
        Assert.Equal(100, events.Last().ProgressPercentage);
    }
}
