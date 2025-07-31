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
        TcpListener tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start();
        int tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        Task<TcpClient> tcpAccept = tcpListener.AcceptTcpClientAsync();

        using UdpClient udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
        Task udpTask = Task.Run(async () => {
            UdpReceiveResult r = await udpServer.ReceiveAsync();
            await udpServer.SendAsync(r.Buffer, r.Buffer.Length, r.RemoteEndPoint);
        });

        DomainHealthCheck healthCheck = new DomainHealthCheck();
        healthCheck.PortScanAnalysis.Timeout = TimeSpan.FromMilliseconds(200);
        await healthCheck.ScanPorts("127.0.0.1", new[] { tcpPort, udpPort });
        using TcpClient _ = await tcpAccept;

        tcpListener.Stop();
        await udpTask;

        List<LogEventArgs> events = healthCheck.GetProgressEvents()
            .Where(e => e.ProgressActivity == "PortScan")
            .ToList();
        Assert.Equal(2, events.Count);
        Assert.Equal(100, events.Last().ProgressPercentage);
    }
}
