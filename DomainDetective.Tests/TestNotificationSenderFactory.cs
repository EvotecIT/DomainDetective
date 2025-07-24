using DomainDetective.Monitoring;

namespace DomainDetective.Tests;

public class TestNotificationSenderFactory
{
    [Fact]
    public void CreatesWebhookSender()
    {
        var url = "https://example.com/hook";
        var sender = NotificationSenderFactory.CreateWebhook(url);
        var webhook = Assert.IsType<WebhookNotificationSender>(sender);
        Assert.Equal(url, webhook.Url);
    }

    [Fact]
    public void CreatesEmailSender()
    {
        var port = PortHelper.GetFreePort();
        var sender = NotificationSenderFactory.CreateEmail("smtp.local", port, false, "from@example.com", "to@example.com", "user", "pass");
        var email = Assert.IsType<EmailNotificationSender>(sender);
        Assert.Equal("smtp.local", email.SmtpHost);
        Assert.Equal(port, email.Port);
        Assert.False(email.UseSsl);
        Assert.Equal("from@example.com", email.From);
        Assert.Equal("to@example.com", email.To);
        Assert.Equal("user", email.Username);
        Assert.Equal("pass", email.Password);
        PortHelper.ReleasePort(port);
    }

    [Fact]
    public void CreatesCustomSender()
    {
        var sender = NotificationSenderFactory.CreateCustom((_, _) => Task.CompletedTask);
        Assert.IsType<DelegateNotificationSender>(sender);
    }
}
