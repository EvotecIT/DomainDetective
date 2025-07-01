using System.Net.Http;
using System.Text;
using MailKit.Net.Smtp;
using MimeKit;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>Defines notification sending behavior.</summary>
public interface INotificationSender
{
    /// <summary>Sends a notification message.</summary>
    Task SendAsync(string message, CancellationToken ct = default);
}

/// <summary>Sends notifications via HTTP webhook.</summary>
public class WebhookNotificationSender : INotificationSender
{
    private readonly HttpClient _client = new();
    public string Url { get; }

    public WebhookNotificationSender(string url)
    {
        Url = url;
    }

    public async Task SendAsync(string message, CancellationToken ct = default)
    {
        using var content = new StringContent(message, Encoding.UTF8, "text/plain");
        await _client.PostAsync(Url, content, ct);
    }
}

/// <summary>Sends notifications via SMTP.</summary>
public class EmailNotificationSender : INotificationSender
{
    public string SmtpHost { get; set; } = "localhost";
    public int Port { get; set; } = 25;
    public bool UseSsl { get; set; }
    public string From { get; set; } = string.Empty;
    public string To { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Password { get; set; }

    public async Task SendAsync(string message, CancellationToken ct = default)
    {
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(From));
        email.To.Add(MailboxAddress.Parse(To));
        email.Subject = "DomainDetective Notification";
        email.Body = new TextPart("plain") { Text = message };

        using var client = new SmtpClient();
        await client.ConnectAsync(SmtpHost, Port, UseSsl, ct);
        if (!string.IsNullOrEmpty(Username))
        {
            await client.AuthenticateAsync(Username, Password ?? string.Empty, ct);
        }
        await client.SendAsync(email, ct);
        await client.DisconnectAsync(true, ct);
    }
}
