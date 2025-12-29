using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

[Collection("PortScan")]
public class TestPortScanExceptions
{
    [Fact]
    public async Task CancellationPropagates()
    {
        var analysis = new PortScanAnalysis();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<TaskCanceledException>(async () =>
            await analysis.Scan("127.0.0.1", new[] { 80 }, new InternalLogger(), cts.Token));
    }
}
