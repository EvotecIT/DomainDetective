using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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
    public bool RequireAttachments { get; set; }
    public string? SubjectContains { get; set; }
    public long MaxAttachmentBytes { get; set; }

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
        if (MaxAttachmentBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxAttachmentBytes), "MaxAttachmentBytes must be >= 0 (0 means unlimited).");
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

        var baseQuery = SearchQuery.All;
        if (options.OnlyUnseen)
        {
            baseQuery = baseQuery.And(SearchQuery.NotSeen);
        }
        if (!string.IsNullOrWhiteSpace(options.SubjectContains))
        {
            baseQuery = baseQuery.And(SearchQuery.SubjectContains(options.SubjectContains!.Trim()));
        }
        if (options.SinceUtc.HasValue)
        {
            // IMAP search operates in local time on some servers; use a conservative date-only filter.
            baseQuery = baseQuery.And(SearchQuery.DeliveredAfter(options.SinceUtc.Value.UtcDateTime.Date));
        }

        var query = options.RequireAttachments ? baseQuery.And(BuildHasAttachmentQuery()) : baseQuery;

        var uids = await folder.SearchAsync(query, cancellationToken).ConfigureAwait(false);
        if (uids.Count == 0 && options.RequireAttachments)
        {
            // Fallback for servers that do not support attachment searches.
            uids = await folder.SearchAsync(baseQuery, cancellationToken).ConfigureAwait(false);
        }
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
                    using var limited = options.MaxAttachmentBytes > 0
                        ? new WriteLimitStream(ms, options.MaxAttachmentBytes, leaveOpen: true)
                        : null;
                    var sink = (Stream?)limited ?? ms;
                    if (attachment is MimePart part)
                    {
                        part.Content.DecodeTo(sink);
                    }
                    else if (attachment is MessagePart messagePart)
                    {
                        messagePart.Message.WriteTo(sink);
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

    private static SearchQuery BuildHasAttachmentQuery()
    {
        try
        {
            var prop = typeof(SearchQuery).GetProperty("HasAttachment", BindingFlags.Public | BindingFlags.Static);
            if (prop != null && prop.GetValue(null) is SearchQuery q)
            {
                return q;
            }
        }
        catch
        {
            // ignore
        }

        // Compatibility fallback: "HasAttachment" is not supported by all MailKit versions / servers.
        // This is not perfect, but it reduces the scan scope on many servers.
        return SearchQuery.HeaderContains("Content-Disposition", "attachment");
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

    private sealed class WriteLimitStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _maxBytes;
        private readonly bool _leaveOpen;
        private long _written;

        public WriteLimitStream(Stream inner, long maxBytes, bool leaveOpen)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (maxBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBytes), "maxBytes must be > 0.");
            _maxBytes = maxBytes;
            _leaveOpen = leaveOpen;
        }

        public override bool CanRead => false;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => true;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush() => _inner.Flush();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

        public override void SetLength(long value)
        {
            if (value > _maxBytes)
            {
                throw new IOException($"WriteLimitStream: requested length {value} exceeds max {_maxBytes} bytes.");
            }
            _inner.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (_written + count > _maxBytes)
            {
                throw new IOException($"WriteLimitStream: wrote {_written} bytes; next write of {count} would exceed max {_maxBytes} bytes.");
            }

            _inner.Write(buffer, offset, count);
            _written += count;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (_written + count > _maxBytes)
            {
                throw new IOException($"WriteLimitStream: wrote {_written} bytes; next write of {count} would exceed max {_maxBytes} bytes.");
            }

            await _inner.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            _written += count;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_leaveOpen)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
