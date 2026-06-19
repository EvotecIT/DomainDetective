using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Monitoring;

namespace DomainDetective.Tests;

public class TestMonitorScheduler
{
    private class CaptureNotifier : INotificationSender
    {
        public readonly System.Collections.Generic.List<string> Messages = new();
        public Task SendAsync(string message, CancellationToken ct = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task TriggersNotificationsOnChange()
    {
        var notifier = new CaptureNotifier();
        var scheduler = new MonitorScheduler
        {
            Notifier = notifier,
            SummaryOverride = _ => Task.FromResult(new DomainSummary { HasMxRecord = true, ExpiryDate = "2025" }),
            CertificateOverride = _ => Task.FromResult(new CertificateMonitor.Entry
            {
                Host = "example.com",
                Expired = true,
                ExpiryDate = System.DateTime.UtcNow.AddDays(-1),
                Analysis = new CertificateAnalysis()
            }),
            BgpOverride = (_, _) => Task.FromResult(new System.Collections.Generic.Dictionary<string, int>())
        };
        scheduler.Domains.Add("example.com");
        await scheduler.RunAsync();

        // next run with different summary should trigger notification
        scheduler.SummaryOverride = _ => Task.FromResult(new DomainSummary { HasMxRecord = false, ExpiryDate = "2025" });
        await scheduler.RunAsync();

        Assert.Contains(notifier.Messages, m => m.Contains("Certificate expired"));
        Assert.Contains(notifier.Messages, m => m.Contains("Changes detected"));
    }

    [Fact]
    public async Task RunAsync_IsThreadSafe()
    {
        var notifier = new CaptureNotifier();
        var callCount = 0;
        var scheduler = new MonitorScheduler
        {
            Notifier = notifier,
            SummaryOverride = async _ =>
            {
                Interlocked.Increment(ref callCount);
                await Task.Delay(100);
                return new DomainSummary { HasMxRecord = true, ExpiryDate = "2025" };
            },
            CertificateOverride = _ => Task.FromResult(new CertificateMonitor.Entry
            {
                Host = "example.com",
                Expired = true,
                ExpiryDate = System.DateTime.UtcNow.AddDays(-1),
                Analysis = new CertificateAnalysis()
            }),
            BgpOverride = (_, _) => Task.FromResult(new System.Collections.Generic.Dictionary<string, int>())
        };
        scheduler.Domains.Add("example.com");

        await Task.WhenAll(scheduler.RunAsync(), scheduler.RunAsync());

        Assert.Equal(1, callCount);
        Assert.Single(notifier.Messages);
    }

    [Fact]
    public async Task AlertsOnBgpChange()
    {
        var notifier = new CaptureNotifier();
        var call = 0;
        var scheduler = new MonitorScheduler
        {
            Notifier = notifier,
            SummaryOverride = _ => Task.FromResult(new DomainSummary { HasMxRecord = true, ExpiryDate = "2025" }),
            CertificateOverride = _ => Task.FromResult(new CertificateMonitor.Entry
            {
                Host = "example.com",
                Expired = false,
                ExpiryDate = System.DateTime.UtcNow.AddDays(10),
                Analysis = new CertificateAnalysis()
            }),
            BgpOverride = (_, _) => Task.FromResult(call++ == 0
                ? new System.Collections.Generic.Dictionary<string, int> { ["1.1.1.0/24"] = 65000 }
                : new System.Collections.Generic.Dictionary<string, int> { ["1.1.1.0/24"] = 65001 })
        };
        scheduler.Domains.Add("example.com");

        await scheduler.RunAsync();
        await scheduler.RunAsync();

        Assert.Contains(notifier.Messages, m => m.Contains("changed"));
    }

    [Fact]
    public void CanStartAndStop()
    {
        var scheduler = new MonitorScheduler();
        var timerField = typeof(MonitorScheduler).GetField("_timer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        scheduler.Start();
        Assert.NotNull(timerField.GetValue(scheduler));
        scheduler.Stop();
        Assert.Null(timerField.GetValue(scheduler));
    }

    [Fact]
    public async Task RunAsync_ProcessesDomainsInParallelWhenConfigured()
    {
        var running = 0;
        var maxRunning = 0;
        var scheduler = new MonitorScheduler
        {
            MaxDomainParallelism = 3,
            SummaryOverride = async domain =>
            {
                var current = Interlocked.Increment(ref running);
                while (true)
                {
                    var observed = Volatile.Read(ref maxRunning);
                    if (current <= observed)
                    {
                        break;
                    }
                    if (Interlocked.CompareExchange(ref maxRunning, current, observed) == observed)
                    {
                        break;
                    }
                }

                try
                {
                    await Task.Delay(80);
                    return new DomainSummary { HasMxRecord = true, ExpiryDate = "2025" };
                }
                finally
                {
                    Interlocked.Decrement(ref running);
                }
            },
            CertificateOverride = _ => Task.FromResult(new CertificateMonitor.Entry
            {
                Host = "example.com",
                Expired = false,
                ExpiryDate = System.DateTime.UtcNow.AddDays(100),
                Analysis = new CertificateAnalysis()
            }),
            BgpOverride = (_, _) => Task.FromResult(new System.Collections.Generic.Dictionary<string, int>())
        };
        scheduler.Domains.AddRange(new[] { "a.example.com", "b.example.com", "c.example.com", "d.example.com" });

        await scheduler.RunAsync();

        Assert.True(maxRunning >= 2);
    }

    [Fact]
    public async Task RunAsyncCancellationWaitsForInFlightDomains()
    {
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = 0;
        var summaryCalls = 0;
        using var cts = new CancellationTokenSource();

        var scheduler = new MonitorScheduler
        {
            MaxDomainParallelism = 1,
            SummaryOverride = async _ =>
            {
                if (Interlocked.Increment(ref summaryCalls) == 1)
                {
                    started.TrySetResult(true);
                    await release.Task;
                    Volatile.Write(ref completed, 1);
                }
                return new DomainSummary { HasMxRecord = true, ExpiryDate = "2025" };
            },
            CertificateOverride = _ => Task.FromResult(new CertificateMonitor.Entry
            {
                Host = "example.com",
                Expired = false,
                ExpiryDate = System.DateTime.UtcNow.AddDays(100),
                Analysis = new CertificateAnalysis()
            }),
            BgpOverride = (_, _) => Task.FromResult(new System.Collections.Generic.Dictionary<string, int>())
        };
        scheduler.Domains.AddRange(new[] { "a.example.com", "b.example.com" });

        var runTask = scheduler.RunAsync(cts.Token);
        await started.Task;
        cts.Cancel();
        release.TrySetResult(true);

        var exception = await Record.ExceptionAsync(() => runTask);
        if (exception != null)
        {
            Assert.IsAssignableFrom<OperationCanceledException>(exception);
        }
        Assert.Equal(1, Volatile.Read(ref completed));
        Assert.True(summaryCalls >= 1);
    }
}
