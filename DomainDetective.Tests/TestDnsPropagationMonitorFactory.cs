using DomainDetective.Monitoring;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnsPropagationMonitorFactory {
    [Fact]
    public void FactoryMethodsSetNotifier() {
        var monitor = new DnsPropagationMonitor { Domain = "example.com" };
        monitor.UseWebhook("https://example.com");
        Assert.IsType<WebhookNotificationSender>(monitor.Notifier);

        var port = PortHelper.GetFreePort();
        monitor.UseEmail("smtp", port, false, "from@e.com", "to@e.com");
        Assert.IsType<EmailNotificationSender>(monitor.Notifier);
        PortHelper.ReleasePort(port);

        monitor.UseCustom((_, _) => Task.CompletedTask);
        Assert.IsType<DelegateNotificationSender>(monitor.Notifier);
    }
}