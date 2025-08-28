using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestNtpAnalysis {
    [Fact]
    public async Task ParsesStratum() {
        using var server = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        var port = ((System.Net.IPEndPoint)server.Client.LocalEndPoint!).Port;
        var task = System.Threading.Tasks.Task.Run(async () => {
            var r = await server.ReceiveAsync();
            var resp = new byte[48];
            resp[0] = 0x24; // LI=0 VN=4 Mode=4 (server)
            resp[1] = 2; // stratum
            ulong ts = (ulong)System.DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 2208988800UL;
            resp[40] = (byte)(ts >> 24);
            resp[41] = (byte)(ts >> 16);
            resp[42] = (byte)(ts >> 8);
            resp[43] = (byte)ts;
            await server.SendAsync(resp, resp.Length, r.RemoteEndPoint);
        });
        try {
            var analysis = new NtpAnalysis { Timeout = System.TimeSpan.FromSeconds(5) };
            await analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger());
            var result = analysis.ServerResults[$"127.0.0.1:{port}"];
            Assert.True(result.Success);
            Assert.Equal((byte)2, result.Stratum);
        } finally {
            await task;
        }
    }

    [Fact]
    public void BuiltinEnumResolvesHost() {
        Assert.Equal("pool.ntp.org", NtpServer.Pool.ToHost());
        Assert.Equal("time.google.com", NtpServer.Google.ToHost());
        Assert.Equal("time.cloudflare.com", NtpServer.Cloudflare.ToHost());
        Assert.Equal("time.nist.gov", NtpServer.Nist.ToHost());
        Assert.Equal("time.windows.com", NtpServer.Windows.ToHost());
    }
}
