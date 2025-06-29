using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestFlatteningServiceAnalysis
{
    private static FlatteningServiceAnalysis Create(string cname)
    {
        return new FlatteningServiceAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.CNAME)
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = cname } });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            }
        };
    }

    [Fact]
    public async Task DetectsFlatteningService()
    {
        var analysis = Create("alias.cloudflare.net");
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.True(analysis.IsFlatteningService);
    }

    [Fact]
    public async Task IgnoresRegularCname()
    {
        var analysis = Create("alias.example.net");
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.False(analysis.IsFlatteningService);
    }

    [Fact]
    public async Task HonorsCancellation()
    {
        using var cts = new CancellationTokenSource();
        var analysis = new FlatteningServiceAnalysis
        {
            QueryDnsOverride = (name, type) => Task.Delay(Timeout.Infinite, cts.Token).ContinueWith(_ => Array.Empty<DnsAnswer>(), cts.Token)
        };

        var task = analysis.Analyze("example.com", new InternalLogger(), cts.Token);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }
}
