using System;
using System.Net.Http;
using System.Text;
using MailKit;
using MailKit.Net.Smtp;
using MimeKit;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>Defines notification sending behavior.</summary>
/// <remarks>
/// Implementations can deliver messages through various channels such as
/// webhooks or email.
/// </remarks>
public interface INotificationSender
{
    /// <summary>Sends a notification message.</summary>
    Task SendAsync(string message, CancellationToken ct = default);
}

/// <summary>Sends notifications via HTTP webhook.</summary>
/// <remarks>
/// The message payload is sent as UTF-8 plain text to the configured URL.
/// </remarks>
public class WebhookNotificationSender : INotificationSender
{
    private readonly HttpClient _client = new();
    /// <summary>Gets the url value.</summary>
    public string Url { get; }

    /// <summary>Initializes a new instance of the WebhookNotificationSender class.</summary>
    public WebhookNotificationSender(string url)
    {
        Url = url;
    }

    /// <summary>Executes the send async operation.</summary>
    public async Task SendAsync(string message, CancellationToken ct = default)
    {
        using var content = new StringContent(message, Encoding.UTF8, "text/plain");
        await _client.PostAsync(Url, content, ct);
    }
}

/// <summary>Sends notifications via SMTP.</summary>
/// <remarks>
/// A plain text email is constructed and sent using the provided SMTP
/// connection information.
/// </remarks>
public class EmailNotificationSender : INotificationSender
{
    internal static Func<ISmtpClient> CreateClient { get; set; } = () => new SmtpClient();
    /// <summary>Gets or sets the smtp host value.</summary>
    public string SmtpHost { get; set; } = "localhost";
    /// <summary>Gets or sets the port value.</summary>
    public int Port { get; set; } = 25;
    /// <summary>Gets or sets the use ssl value.</summary>
    public bool UseSsl { get; set; }
    /// <summary>Gets or sets the from value.</summary>
    public string From { get; set; } = string.Empty;
    /// <summary>Gets or sets the to value.</summary>
    public string To { get; set; } = string.Empty;
    /// <summary>Gets or sets the username value.</summary>
    public string? Username { get; set; }
    /// <summary>Gets or sets the password value.</summary>
    public string? Password { get; set; }

    /// <summary>Executes the send async operation.</summary>
    public async Task SendAsync(string message, CancellationToken ct = default)
    {
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(From));
        email.To.Add(MailboxAddress.Parse(To));
        email.Subject = "DomainDetective Notification";
        email.Body = new TextPart("plain") { Text = message };

        using var client = CreateClient();
        await client.ConnectAsync(SmtpHost, Port, UseSsl, ct);
        if (!string.IsNullOrEmpty(Username))
        {
            await client.AuthenticateAsync(Username, Password ?? string.Empty, ct);
        }
        await client.SendAsync(email, ct);
        await client.DisconnectAsync(true, ct);
    }
}
