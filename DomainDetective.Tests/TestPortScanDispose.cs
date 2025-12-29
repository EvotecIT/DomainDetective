using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestPortScanDispose
{
    private class CountingTcpClient : TcpClient
    {
        public static int DisposeCount { get; set; }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeCount++;
            }
            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task TcpClientIsDisposedAfterScan()
    {
        CountingTcpClient.DisposeCount = 0;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();
        var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
        analysis.TcpClientFactory = _ => new CountingTcpClient();

        try
        {
            await analysis.Scan("127.0.0.1", new[] { port }, new InternalLogger());
            using var _ = await acceptTask; // ensure connection completes
        }
        finally
        {
            listener.Stop();
        }

        Assert.Equal(1, CountingTcpClient.DisposeCount);
    }
}
