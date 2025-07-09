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
            })
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
            })
        };
        scheduler.Domains.Add("example.com");

        await Task.WhenAll(scheduler.RunAsync(), scheduler.RunAsync());

        Assert.Equal(1, callCount);
        Assert.Single(notifier.Messages);
    }
}
