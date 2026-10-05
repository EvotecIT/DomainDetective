using DnsClientX;
using DomainDetective.Monitoring;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestMonitorCancellation {
    private static TaskCompletionSource<bool> Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Fact]
    public async Task CertificateTimerPassesItsStopTokenIntoActiveAnalysis() {
        var entered = Signal();
        var release = Signal();
        CancellationToken observed = default;
        using var monitor = new CertificateMonitor {
            AnalysisOverride = async (_, _, _, ct) => {
                observed = ct;
                entered.TrySetResult(true);
                await release.Task.WaitWithCancellation(ct);
                return new CertificateAnalysis();
            }
        };
        monitor.Start(new[] { "https://example.test" }, TimeSpan.FromHours(1));
        try {
            await entered.Task;
            Assert.True(observed.CanBeCanceled);
            await monitor.StopAsync();
            Assert.True(observed.IsCancellationRequested);
            Assert.Empty(monitor.Results);
        } finally {
            release.TrySetResult(true);
            await monitor.StopAsync();
        }
    }

    [Fact]
    public async Task RestartCannotUseOrBeClearedByThePreviousCancellationGeneration() {
        var oldEntered = Signal();
        var oldCanceled = Signal();
        var oldRelease = Signal();
        var newEntered = Signal();
        var newRelease = Signal();
        CancellationToken newToken = default;
        using var monitor = new CertificateMonitor {
            AnalysisOverride = async (url, _, _, ct) => {
                if (url.Contains("old.example", StringComparison.Ordinal)) {
                    using var registration = ct.Register(() => oldCanceled.TrySetResult(true));
                    oldEntered.TrySetResult(true);
                    await oldRelease.Task;
                    ct.ThrowIfCancellationRequested();
                } else {
                    newToken = ct;
                    newEntered.TrySetResult(true);
                    await newRelease.Task.WaitWithCancellation(ct);
                }
                return new CertificateAnalysis();
            }
        };
        monitor.Start(new[] { "https://old.example" }, TimeSpan.FromHours(1));
        await oldEntered.Task;
        Task stopping = monitor.StopAsync();
        await oldCanceled.Task;
        Task starting = Task.Run(() => monitor.Start(new[] { "https://new.example" }, TimeSpan.FromHours(1)));
        try {
            oldRelease.TrySetResult(true);
            await Task.WhenAll(stopping, starting);
            await newEntered.Task;
            Assert.True(monitor.IsRunning);
            Assert.True(newToken.CanBeCanceled);
            Assert.False(newToken.IsCancellationRequested);
            await monitor.StopAsync();
            Assert.True(newToken.IsCancellationRequested);
            Assert.False(monitor.IsRunning);
            Assert.Empty(monitor.Results);
        } finally {
            oldRelease.TrySetResult(true); newRelease.TrySetResult(true);
            await monitor.StopAsync();
        }
    }

    [Fact]
    public async Task SchedulerStopCancelsItsActiveDomainBeforeLaterStages() {
        var entered = Signal();
        var release = Signal();
        int certificateCalls = 0;
        var scheduler = new MonitorScheduler {
            SummaryOverride = async _ => { entered.TrySetResult(true); await release.Task; return new DomainSummary(); },
            CertificateOverride = _ => { Interlocked.Increment(ref certificateCalls); return Task.FromResult(new CertificateMonitor.Entry { Analysis = new CertificateAnalysis() }); },
            BgpOverride = (_, _) => Task.FromResult(new Dictionary<string, int>())
        };
        scheduler.Domains.Add("example.test");
        scheduler.Start();
        await entered.Task;
        Task stopping = scheduler.StopAsync();
        bool stopped = await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(5))) == stopping;
        release.TrySetResult(true);
        await stopping;
        Assert.True(stopped, "Stop must interrupt the wait for a caller-owned legacy summary callback.");
        Assert.Equal(0, certificateCalls);
    }

    [Fact]
    public async Task CallerCancellationDoesNotCommitOrNotifyAfterLegacySummaryCompletes() {
        var entered = Signal();
        var release = Signal();
        int certificateCalls = 0;
        var scheduler = new MonitorScheduler {
            SummaryOverride = async _ => { entered.TrySetResult(true); await release.Task; return new DomainSummary(); },
            CertificateOverride = _ => { Interlocked.Increment(ref certificateCalls); return Task.FromResult(new CertificateMonitor.Entry { Analysis = new CertificateAnalysis() }); },
            BgpOverride = (_, _) => Task.FromResult(new Dictionary<string, int>())
        };
        scheduler.Domains.Add("example.test");
        using var cancellation = new CancellationTokenSource();
        Task run = scheduler.RunAsync(cancellation.Token);
        await entered.Task;
        cancellation.Cancel();
        bool stopped = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(5))) == run;
        release.TrySetResult(true);
        var error = await Record.ExceptionAsync(() => run);
        Assert.True(stopped, "Caller cancellation must bound the callback wait.");
        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.Equal(0, certificateCalls);
    }

    [Fact]
    public async Task WildcardCheckPropagatesCallerCancellationDuringDnsLookup() {
        var entered = Signal();
        var release = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new DomainHealthCheck();
        health.WildcardDnsAnalysis.QueryDnsOverride = (_, _) => { entered.TrySetResult(true); return release.Task; };
        using var cancellation = new CancellationTokenSource();
        Task run = health.Verify("example.test", new[] { HealthCheckType.WILDCARDDNS }, cancellationToken: cancellation.Token);
        await entered.Task;
        cancellation.Cancel();
        bool stopped = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(5))) == run;
        release.TrySetResult(Array.Empty<DnsAnswer>());
        var error = await Record.ExceptionAsync(() => run);
        Assert.True(stopped, "Wildcard DNS must receive the health-check caller token.");
        Assert.IsAssignableFrom<OperationCanceledException>(error);
        Assert.False(health.WildcardDnsAnalysis.CatchAll);
    }    [Fact]
    public async Task ConfiguredDnsProviderCannotHoldWildcardCancellationOpen() {
        var entered = Signal();
        var release = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, _) => { entered.TrySetResult(true); return release.Task; };
        using var cancellation = new CancellationTokenSource();
        Task run = health.Verify("example.test", new[] { HealthCheckType.WILDCARDDNS }, cancellationToken: cancellation.Token);
        await entered.Task;
        cancellation.Cancel();
        bool canceled = await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(5))) == run;
        release.TrySetResult(Array.Empty<DnsAnswer>());
        var error = await Record.ExceptionAsync(() => run);
        Assert.True(canceled, "The shared configured DNS provider must have a cancellable wait.");
        Assert.IsAssignableFrom<OperationCanceledException>(error);
    }

    [Fact]
    public async Task CancellationFromFinalProgressCannotPublishACertificateBatch() {
        using var cancellation = new CancellationTokenSource();
        var logger = new InternalLogger();
        logger.OnProgressMessage += (_, _) => cancellation.Cancel();
        using var monitor = new CertificateMonitor { AnalysisOverride = (_, _, _, _) => Task.FromResult(new CertificateAnalysis { IsValid = true }) };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => monitor.Analyze(new[] { "https://example.test" }, logger: logger, cancellationToken: cancellation.Token));
        Assert.Empty(monitor.Results);
    }

    [Theory]
    [InlineData("summary")]
    [InlineData("expiry")]
    public async Task CancellationFromNotificationStopsStatePublicationAndFollowingStages(string stage) {
        using var cancellation = new CancellationTokenSource();
        int certificateCalls = 0, bgpCalls = 0;
        bool changed = false;
        var scheduler = new MonitorScheduler {
            SummaryOverride = _ => Task.FromResult(new DomainSummary { HasMxRecord = !changed }),
            CertificateOverride = _ => { certificateCalls++; return Task.FromResult(new CertificateMonitor.Entry { Expired = stage == "expiry", ExpiryDate = DateTime.UtcNow.AddDays(100), Analysis = new CertificateAnalysis() }); },
            BgpOverride = (_, _) => { bgpCalls++; return Task.FromResult(new Dictionary<string, int>()); }
        };
        scheduler.Domains.Add("example.test");
        if (stage == "summary") { await scheduler.RunAsync(); changed = true; }
        int previousCertificates = certificateCalls, previousBgp = bgpCalls;
        scheduler.Notifier = new CancellingNotifier(() => cancellation.Cancel());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scheduler.RunAsync(cancellation.Token));
        Assert.Equal(previousCertificates + (stage == "expiry" ? 1 : 0), certificateCalls);
        Assert.Equal(previousBgp, bgpCalls);
    }

    private sealed class CancellingNotifier : INotificationSender {
        private readonly Action _cancel;
        internal CancellingNotifier(Action cancel) => _cancel = cancel;
        public Task SendAsync(string message, CancellationToken ct = default) { _cancel(); return Task.CompletedTask; }
    }

}
