using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MimeKit;

namespace DomainDetective.TimeSeries;

public sealed class ImapAttachmentIngestOptions
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 993;
    public bool UseSsl { get; set; } = true;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Mailbox { get; set; } = "INBOX";
    public DateTimeOffset? SinceUtc { get; set; }
    public int MaxMessages { get; set; } = 500;
    public bool OnlyUnseen { get; set; }

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host))
        {
            throw new ArgumentException("IMAP host is required.", nameof(Host));
        }
        if (Port <= 0 || Port > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(Port), "IMAP port must be between 1 and 65535.");
        }
        if (string.IsNullOrWhiteSpace(Username))
        {
            throw new ArgumentException("IMAP username is required.", nameof(Username));
        }
        if (Password == null)
        {
            throw new ArgumentNullException(nameof(Password));
        }
        if (string.IsNullOrWhiteSpace(Mailbox))
        {
            throw new ArgumentException("IMAP mailbox is required.", nameof(Mailbox));
        }
    }
}

public sealed class ImapAttachmentIngestResult<T>
{
    public List<T> Items { get; } = new();
    public List<string> Errors { get; } = new();
}

public static class ImapAttachmentIngestor
{
    public static async Task<ImapAttachmentIngestResult<T>> IngestAsync<T>(
        ImapAttachmentIngestOptions options,
        Func<string, bool> includeAttachmentFileName,
        Func<Stream, string, CancellationToken, Task<T?>> parseAsync,
        CancellationToken cancellationToken = default)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        if (includeAttachmentFileName == null) throw new ArgumentNullException(nameof(includeAttachmentFileName));
        if (parseAsync == null) throw new ArgumentNullException(nameof(parseAsync));

        options.Validate();

        var result = new ImapAttachmentIngestResult<T>();

        using var client = new ImapClient();
        await client.ConnectAsync(options.Host, options.Port, options.UseSsl, cancellationToken).ConfigureAwait(false);
        await client.AuthenticateAsync(options.Username, options.Password, cancellationToken).ConfigureAwait(false);

        var folder = await client.GetFolderAsync(options.Mailbox, cancellationToken).ConfigureAwait(false);
        await folder.OpenAsync(FolderAccess.ReadOnly, cancellationToken).ConfigureAwait(false);

        var query = SearchQuery.All;
        if (options.OnlyUnseen)
        {
            query = query.And(SearchQuery.NotSeen);
        }
        if (options.SinceUtc.HasValue)
        {
            // IMAP search operates in local time on some servers; use a conservative date-only filter.
            query = query.And(SearchQuery.DeliveredAfter(options.SinceUtc.Value.UtcDateTime.Date));
        }

        var uids = await folder.SearchAsync(query, cancellationToken).ConfigureAwait(false);
        if (options.MaxMessages > 0)
        {
            uids = uids.Take(options.MaxMessages).ToList();
        }

        foreach (var uid in uids)
        {
            cancellationToken.ThrowIfCancellationRequested();

            MimeMessage? msg = null;
            try
            {
                msg = await folder.GetMessageAsync(uid, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.Errors.Add($"IMAP: failed to fetch message {uid}: {ex.Message}");
                continue;
            }

            foreach (var attachment in msg.Attachments ?? Array.Empty<MimeEntity>())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var fileName = GetFileName(attachment);
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    continue;
                }
                var normalizedFileName = fileName!.Trim();
                if (!includeAttachmentFileName(normalizedFileName))
                {
                    continue;
                }

                try
                {
                    using var ms = new MemoryStream();
                    if (attachment is MimePart part)
                    {
                        part.Content.DecodeTo(ms);
                    }
                    else if (attachment is MessagePart messagePart)
                    {
                        messagePart.Message.WriteTo(ms);
                    }
                    else
                    {
                        continue;
                    }

                    ms.Position = 0;
                    var parsed = await parseAsync(ms, normalizedFileName, cancellationToken).ConfigureAwait(false);
                    if (parsed != null)
                    {
                        result.Items.Add(parsed);
                    }
                }
                catch (Exception ex)
                {
                    var id = msg.MessageId ?? uid.ToString();
                    result.Errors.Add($"IMAP: failed to parse attachment '{normalizedFileName}' from message '{id}': {ex.Message}");
                }
            }
        }

        await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false);
        return result;
    }

    private static string? GetFileName(MimeEntity attachment)
    {
        if (attachment is MimePart part)
        {
            return part.FileName ?? part.ContentDisposition?.FileName ?? part.ContentType?.Name;
        }

        if (attachment is MessagePart mp)
        {
            return mp.ContentDisposition?.FileName ?? mp.ContentType?.Name;
        }

        return attachment.ContentDisposition?.FileName;
    }
}
