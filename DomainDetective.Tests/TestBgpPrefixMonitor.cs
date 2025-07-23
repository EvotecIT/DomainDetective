using DomainDetective.Monitoring;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestBgpPrefixMonitor
{
    private class CaptureNotifier : INotificationSender
    {
        public readonly List<string> Messages = new();
        public Task SendAsync(string message, CancellationToken ct = default)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task SendsNotificationOnAsChange()
    {
        var notifier = new CaptureNotifier();
        var results = new[]
        {
            new Dictionary<string, int> { ["1.1.1.0/24"] = 65000 },
            new Dictionary<string, int> { ["1.1.1.0/24"] = 65001 }
        };
        var call = 0;
        var monitor = new BgpPrefixMonitor
        {
            Domain = "example.com",
            Notifier = notifier,
            QueryOverride = _ => Task.FromResult(results[call++])
        };
        await monitor.RunAsync();
        await monitor.RunAsync();
        Assert.Contains(notifier.Messages, m => m.Contains("changed"));
    }

    [Fact]
    public void CanStartAndStopMultipleTimes()
    {
        var monitor = new BgpPrefixMonitor
        {
            Domain = "example.com",
            QueryOverride = _ => Task.FromResult(new Dictionary<string, int>())
        };
        var timerField = typeof(BgpPrefixMonitor).GetField("_timer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        for (int i = 0; i < 3; i++)
        {
            monitor.Start();
            Assert.NotNull(timerField.GetValue(monitor));
            monitor.Stop();
            Assert.Null(timerField.GetValue(monitor));
        }
    }

    [Fact]
    public void FactoryMethodsSetNotifier()
    {
        var monitor = new BgpPrefixMonitor { Domain = "example.com" };
        monitor.UseWebhook("https://example.com");
        Assert.IsType<WebhookNotificationSender>(monitor.Notifier);

        monitor.UseEmail("smtp", 25, false, "from@e.com", "to@e.com");
        Assert.IsType<EmailNotificationSender>(monitor.Notifier);

        monitor.UseCustom((_, _) => Task.CompletedTask);
        Assert.IsType<DelegateNotificationSender>(monitor.Notifier);
    }
}
