using DnsClientX;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestEdnsSupportAnalysis {
    private static EdnsSupportAnalysis Create(bool support) {
        return new EdnsSupportAnalysis {
            QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.NS) {
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
    public async Task ParsesUdpPayloadAndDoBit(int size, bool doBit) {
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.NS) {
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
    public async Task ReportsSupport() {
        var analysis = Create(true);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => v.Supported);
    }

    [Fact]
    public async Task ReportsNoSupport() {
        var analysis = Create(false);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Contains(analysis.ServerSupport.Values, v => !v.Supported);
    }

    [Fact]
    public async Task RetriesOverTcpWhenTruncated() {
        var port = PortHelper.GetFreePort();
        UdpClient? udpServer = null;
        TcpListener? tcpListener = null;
        Task? udpTask = null;
        Task? tcpTask = null;

        try {
            tcpListener = new TcpListener(IPAddress.Loopback, port);
            tcpListener.Start();
            udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));

            var udp = udpServer;
            var listener = tcpListener;

            udpTask = Task.Run(async () => {
                var r = await udp.ReceiveAsync();
                var q = r.Buffer;
                var resp = new byte[12];
                resp[0] = q[0];
                resp[1] = q[1];
                resp[2] = (byte)(0x80 | 0x02 | (q[2] & 0x01));
                resp[3] = 0x00;
                await udp.SendAsync(resp, resp.Length, r.RemoteEndPoint);
            });

            tcpTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();

                var prefix = new byte[2];
                await ReadExactlyAsync(stream, prefix, 0, prefix.Length);
                int len = prefix[0] << 8 | prefix[1];

                var q = new byte[len];
                if (len > 0) {
                    await ReadExactlyAsync(stream, q, 0, q.Length);
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

                var respPrefix = new[] { (byte)(resp.Length >> 8), (byte)(resp.Length & 0xFF) };
                await stream.WriteAsync(respPrefix, 0, respPrefix.Length);
                await stream.WriteAsync(resp, 0, resp.Length);
            });

            var analysis = new EdnsSupportAnalysis {
                QueryDnsOverride = (name, type) => {
                    if (type == DnsRecordType.NS) {
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
            Assert.True(result.TruncatedUdp);
        }
        finally {
            try {
                tcpListener?.Stop();
            } catch {
                // ignore cleanup failures
            }

            udpServer?.Dispose();
            PortHelper.ReleasePort(port);

            if (udpTask != null) {
                try {
                    await udpTask;
                } catch {
                    // ignore cleanup failures
                }
            }

            if (tcpTask != null) {
                try {
                    await tcpTask;
                } catch {
                    // ignore cleanup failures
                }
            }
        }
    }

    [Fact]
    public async Task UsesRequestedDomainInEdnsProbe() {
        var port = PortHelper.GetFreePort();
        string? queryName = null;
        using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        var udpTask = Task.Run(async () => {
            var request = await udpServer.ReceiveAsync();
            queryName = ReadQueryName(request.Buffer);
            var q = request.Buffer;
            var response = new byte[23];
            response[0] = q[0];
            response[1] = q[1];
            response[2] = (byte)(0x80 | (q[2] & 0x01));
            response[3] = 0x00;
            response[10] = 0x00;
            response[11] = 0x01;
            response[12] = 0x00;
            response[13] = 0x00;
            response[14] = 0x29;
            response[15] = 0x10;
            response[16] = 0x00;
            response[17] = 0x00;
            response[18] = 0x00;
            response[19] = 0x00;
            response[20] = 0x00;
            response[21] = 0x00;
            response[22] = 0x00;
            await udpServer.SendAsync(response, response.Length, request.RemoteEndPoint);
        });

        try {
            var analysis = new EdnsSupportAnalysis {
                QueryDnsOverride = (name, type) => {
                    if (type == DnsRecordType.NS) {
                        return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                    }

                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = $"127.0.0.1:{port}", Type = DnsRecordType.A } });
                }
            };

            await analysis.Analyze("contoso.example", new InternalLogger());
            Assert.Equal("contoso.example", queryName);
        }
        finally {
            udpServer.Dispose();
            PortHelper.ReleasePort(port);
            await udpTask;
        }
    }

    [Fact]
    public async Task UsesIpv6AuthoritativeServerAddressesWhenIpv4Missing() {
        var seenAddresses = new List<string>();
        var analysis = new EdnsSupportAnalysis {
            QueryDnsOverride = (name, type) => {
                if (type == DnsRecordType.NS) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns.example.com", Type = DnsRecordType.NS } });
                }
                if (type == DnsRecordType.AAAA) {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "2001:db8::53", Type = DnsRecordType.AAAA } });
                }

                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            QueryServerOverride = serverAddress => {
                seenAddresses.Add(serverAddress);
                return Task.FromResult(new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = false });
            }
        };

        await analysis.Analyze("example.com", new InternalLogger());

        Assert.Contains("2001:db8::53", seenAddresses);
        Assert.Contains(analysis.ServerSupport.Keys, key => key.Contains("2001:db8::53", StringComparison.Ordinal));
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer, int offset, int count) {
        int total = 0;
        while (total < count) {
            int read = await stream.ReadAsync(buffer, offset + total, count - total);
            if (read == 0) {
                throw new IOException("Stream closed before expected bytes were read.");
            }
            total += read;
        }
    }

    private static string ReadQueryName(byte[] message) {
        var offset = 12;
        var labels = new List<string>();
        while (offset < message.Length) {
            var length = message[offset++];
            if (length == 0) {
                break;
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(message, offset, length));
            offset += length;
        }

        return string.Join(".", labels);
    }
}
