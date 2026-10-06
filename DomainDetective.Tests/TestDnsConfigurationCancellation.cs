using System;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsConfigurationCancellation {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyAnswerCallbackDoesNotHoldCanceledCaller(bool response) {
        using var caller = new CancellationTokenSource();
        var callback = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var configuration = new DnsConfiguration { QueryDnsOverride = (_, _) => callback.Task };
        Task run = response ? configuration.QueryDNSResponse("example.test", DnsRecordType.NS, cancellationToken: caller.Token)
            : configuration.QueryDNS("example.test", DnsRecordType.NS, cancellationToken: caller.Token);
        try {
            caller.Cancel();
            Assert.Same(run, await Task.WhenAny(run, Task.Delay(1500)));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        } finally {
            callback.TrySetResult(Array.Empty<DnsAnswer>());
            try { await run; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task HealthBudgetBoundsConfiguredLegacyDiscoveryWithoutFalseHealth() {
        var callback = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new DnsHealthAnalysis {
            DnsConfiguration = new DnsConfiguration { QueryDnsOverride = (_, _) => callback.Task },
            AnalysisTimeoutMilliseconds = 100
        };
        Task run = analysis.Analyze("example.test", new InternalLogger());
        try {
            Assert.Same(run, await Task.WhenAny(run, Task.Delay(1500)));
            await run;
            Assert.False(analysis.DiscoveryComplete);
            Assert.False(analysis.ServersResponsive);
        } finally { callback.TrySetResult(Array.Empty<DnsAnswer>()); await run; }
    }
}
