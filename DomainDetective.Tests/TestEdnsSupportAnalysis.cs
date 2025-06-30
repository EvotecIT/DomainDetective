using DnsClientX;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestEdnsSupportAnalysis
{
    private static EdnsSupportAnalysis Create(bool support)
    {
        return new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                }
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = support, UdpPayloadSize = 4096, DoBit = true })
        };
    }

    [Theory]
    [InlineData(512, false)]
    [InlineData(4096, true)]
    public async Task ParsesUdpPayloadAndDoBit(int size, bool doBit)
    {
        var analysis = new EdnsSupportAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS)
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                }
                return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1", Type = DnsRecordType.A } });
            },
            QueryServerOverride = _ => Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = size, DoBit = doBit })
        };

        await analysis.Analyze("example.com", new InternalLogger());
        var result = analysis.ServerSupport.Values.First();
        Assert.Equal(size, result.UdpPayloadSize);
        Assert.Equal(doBit, result.DoBit);
    }

    [Fact]
    public async Task ReportsSupport()
    {
        var analysis = Create(true);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => v.Supported);
    }

    [Fact]
    public async Task ReportsNoSupport()
    {
        var analysis = Create(false);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => !v.Supported);
    }

    [Fact]
    public async Task RetriesOverTcpWhenTruncated()
    {
        var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
        var tcpListener = new TcpListener(IPAddress.Loopback, port);
        tcpListener.Start();

        var udpTask = Task.Run(async () =>
        {
            var r = await udpServer.ReceiveAsync();
            var q = r.Buffer;
            var resp = new byte[12];
            resp[0] = q[0];
            resp[1] = q[1];
            resp[2] = (byte)(0x80 | 0x02 | (q[2] & 0x01));
            resp[3] = 0x00;
            await udpServer.SendAsync(resp, resp.Length, r.RemoteEndPoint);
        });

        var tcpTask = Task.Run(async () =>
        {
            using var client = await tcpListener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var buf = new byte[2];
            await stream.ReadAsync(buf, 0, 2);
            int len = buf[0] << 8 | buf[1];
            var q = new byte[len];
            if (len > 0)
            {
                await stream.ReadAsync(q, 0, len);
            }
            var resp = new byte[23];
            resp[0] = q[0];
            resp[1] = q[1];
            resp[2] = (byte)(0x80 | (q[2] & 0x01));
            resp[3] = 0x00;
            resp[10] = 0x00;
            resp[11] = 0x01;
            resp[12] = 0x00;
            resp[13] = 0x00;
            resp[14] = 0x29;
            resp[15] = 0x10;
            resp[16] = 0x00;
            resp[17] = 0x00;
            resp[18] = 0x00;
            resp[19] = 0x00;
            resp[20] = 0x00;
            resp[21] = 0x00;
            resp[22] = 0x00;
            var prefix = new byte[] { (byte)(resp.Length >> 8), (byte)(resp.Length & 0xFF) };
            await stream.WriteAsync(prefix, 0, 2);
            await stream.WriteAsync(resp, 0, resp.Length);
        });

        try
        {
            var analysis = new EdnsSupportAnalysis
            {
                QueryDnsOverride = (name, type) =>
                {
                    if (type == DnsRecordType.NS)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                    }
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = $"127.0.0.1:{port}", Type = DnsRecordType.A } });
                }
            };

            await analysis.Analyze("example.com", new InternalLogger());
            var result = analysis.ServerSupport.Values.First();
            Assert.True(result.Supported);
            Assert.Equal(4096, result.UdpPayloadSize);
            Assert.False(result.DoBit); 
        }
        finally
        {
            udpServer.Close();
            tcpListener.Stop();
            await udpTask;
            await tcpTask;
        }
    }
}
