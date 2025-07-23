using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring;

/// <summary>Creates configured notification senders.</summary>
public static class NotificationSenderFactory
{
    /// <summary>
    /// Creates a webhook notification sender.
    /// </summary>
    /// <param name="url">Webhook URL.</param>
    public static INotificationSender CreateWebhook(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            throw new ArgumentException("URL cannot be null or empty", nameof(url));
        }

        return new WebhookNotificationSender(url);
    }

    /// <summary>
    /// Creates a notification sender using a custom delegate.
    /// </summary>
    /// <param name="handler">Delegate invoked to deliver the message.</param>
    public static INotificationSender CreateCustom(Func<string, CancellationToken, Task> handler)
    {
        if (handler == null)
        {
            throw new ArgumentNullException(nameof(handler));
        }

        return new DelegateNotificationSender(handler);
    }

    /// <summary>
    /// Creates an email notification sender.
    /// </summary>
    /// <param name="smtpHost">SMTP server host.</param>
    /// <param name="port">SMTP server port.</param>
    /// <param name="useSsl">Whether to use SSL.</param>
    /// <param name="from">Sender email address.</param>
    /// <param name="to">Recipient email address.</param>
    /// <param name="username">SMTP username.</param>
    /// <param name="password">SMTP password.</param>
    public static INotificationSender CreateEmail(string smtpHost, int port, bool useSsl, string from, string to, string? username = null, string? password = null)
    {
        if (string.IsNullOrWhiteSpace(smtpHost))
        {
            throw new ArgumentException("SMTP host cannot be null or empty", nameof(smtpHost));
        }

        if (string.IsNullOrWhiteSpace(from))
        {
            throw new ArgumentException("Sender address cannot be null or empty", nameof(from));
        }

        if (string.IsNullOrWhiteSpace(to))
        {
            throw new ArgumentException("Recipient address cannot be null or empty", nameof(to));
        }

        return new EmailNotificationSender
        {
            SmtpHost = smtpHost,
            Port = port,
            UseSsl = useSsl,
            From = from,
            To = to,
            Username = username,
            Password = password
        };
    }
}
