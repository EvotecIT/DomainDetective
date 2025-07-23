using DomainDetective.Monitoring;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Example demonstrating NotificationSenderFactory.
    /// </summary>
    public static async Task ExampleNotificationFactory() {
        var webhook = NotificationSenderFactory.CreateWebhook("https://example.com/hook");
        var email = NotificationSenderFactory.CreateEmail("smtp.example.com", 25, false, "from@example.com", "to@example.com");
        var custom = NotificationSenderFactory.CreateCustom((m, _) => {
            Console.WriteLine(m);
            return Task.CompletedTask;
        });

        await webhook.SendAsync("Webhook message");
        await email.SendAsync("Email message");
        await custom.SendAsync("Custom message");
    }
}