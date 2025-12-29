using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestSocketExhaustion
{
    [Fact]
    public async Task HandlesSocketCreationFailures()
    {
        var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(10) };
        int count = 0;
        analysis.UdpClientFactory = af =>
        {
            if (Interlocked.Increment(ref count) > 3)
            {
                throw new SocketException((int)SocketError.TooManyOpenSockets);
            }

            return new UdpClient(af);
        };

        await analysis.Scan("127.0.0.1", new[] { 1, 2, 3, 4, 5 }, new InternalLogger());
        Assert.Contains(analysis.Results.Values, r => r.Error != null);
    }
}
