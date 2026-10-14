using DomainDetective.TimeSeries;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DomainDetective.Tests;

public class TestImapReportLimits {
    [Theory]
    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task RawMessageLimitStopsAdvertisedAndUnadvertisedOversizedMessages(bool honestSize, bool includeSize) {
        await using var server = new ImapFixture(new string('x', 8192), honestSize, includeSize);
        int parsed = 0;
        var options = server.Options();
        options.MaxMessageBytes = 1024;

        var result = await ImapAttachmentIngestor.IngestAsync<string>(options, _ => true,
            (_, _, _) => { Interlocked.Increment(ref parsed); return Task.FromResult<string?>("parsed"); });

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, error => error.Contains("max size 1024"));
        Assert.Equal(0, parsed);
        Assert.Equal(honestSize && includeSize ? 0 : 1, server.BodyRequests);
    }

    [Fact]
    public async Task AttachmentLimitIsIndependentOfRawMessageLimit() {
        await using var server = new ImapFixture(new string('x', 2048), true, true);
        var options = server.Options();
        options.MaxMessageBytes = 16 * 1024;
        options.MaxAttachmentBytes = 1024;
        int parsed = 0;

        var result = await ImapAttachmentIngestor.IngestAsync<string>(options, _ => true,
            (_, _, _) => { Interlocked.Increment(ref parsed); return Task.FromResult<string?>("parsed"); });

        Assert.Empty(result.Items);
        Assert.Contains(result.Errors, error => error.Contains("exceed max 1024"));
        Assert.Equal(0, parsed);
    }

    [Fact]
    public async Task ExplicitUnlimitedMessageAndAttachmentLimitsAllowContent() {
        await using var server = new ImapFixture(new string('x', 2048), true, true);
        var options = server.Options();
        options.MaxMessageBytes = 0;
        options.MaxAttachmentBytes = 0;

        var result = await ImapAttachmentIngestor.IngestAsync<string>(options, _ => true,
            async (stream, _, _) => { using var reader = new StreamReader(stream); return await reader.ReadToEndAsync(); });

        Assert.Empty(result.Errors);
        Assert.Equal(new string('x', 2048), Assert.Single(result.Items));
    }

    [Fact]
    public async Task CallerCancellationDuringAttachmentParsingPropagates() {
        await using var server = new ImapFixture("small", true, true);
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ImapAttachmentIngestor.IngestAsync<string>(
            server.Options(), _ => true, (_, _, token) => {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
                return Task.FromResult<string?>("unreachable");
            }, cancellation.Token));
    }

    private sealed class ImapFixture : IAsyncDisposable {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(15));
        private readonly byte[] _message;
        private readonly bool _honestSize;
        private readonly bool _includeSize;
        private readonly Task _server;
        private TcpClient? _peer;
        private int _bodyRequests;
        internal int BodyRequests => Volatile.Read(ref _bodyRequests);

        internal ImapFixture(string attachment, bool honestSize, bool includeSize) {
            _honestSize = honestSize;
            _includeSize = includeSize;
            _message = Encoding.ASCII.GetBytes("From: sender@example.com\r\nTo: reports@example.com\r\n" +
                "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=limit\r\n\r\n" +
                "--limit\r\nContent-Type: application/json\r\nContent-Disposition: attachment; filename=report.json\r\n" +
                "Content-Transfer-Encoding: base64\r\n\r\n" + Convert.ToBase64String(Encoding.ASCII.GetBytes(attachment)) + "\r\n--limit--\r\n");
            _listener.Start();
            _server = ServeAsync();
        }

        internal ImapAttachmentIngestOptions Options() => new() {
            Host = "127.0.0.1", Port = ((IPEndPoint)_listener.LocalEndpoint).Port,
            UseSsl = false, Username = "fixture", Password = "disposable-fixture", MaxMessages = 1
        };

        private async Task ServeAsync() {
            try {
                using var peer = await _listener.AcceptTcpClientAsync();
                _peer = peer;
                using var stream = peer.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                using var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };
                await writer.WriteLineAsync("* OK [CAPABILITY IMAP4rev1] fixture");
                while (!_stop.IsCancellationRequested) {
                    string? command = await reader.ReadLineAsync();
                    if (command == null) return;
                    string tag = command.Split(' ')[0];
                    if (command.Contains(" LOGIN ")) {
                        await writer.WriteLineAsync(tag + " OK [CAPABILITY IMAP4rev1] logged in");
                    } else if (command.Contains(" CAPABILITY")) {
                        await writer.WriteLineAsync("* CAPABILITY IMAP4rev1");
                        await writer.WriteLineAsync(tag + " OK capability");
                    } else if (command.Contains(" LIST ")) {
                        await writer.WriteLineAsync("* LIST (\\HasNoChildren) \"/\" \"INBOX\"");
                        await writer.WriteLineAsync(tag + " OK list");
                    } else if (command.Contains(" EXAMINE ")) {
                        await writer.WriteLineAsync("* FLAGS (\\Seen)");
                        await writer.WriteLineAsync("* 1 EXISTS");
                        await writer.WriteLineAsync("* OK [UIDVALIDITY 1] valid");
                        await writer.WriteLineAsync("* OK [UIDNEXT 2] next");
                        await writer.WriteLineAsync(tag + " OK [READ-ONLY] opened");
                    } else if (command.Contains(" SEARCH ")) {
                        await writer.WriteLineAsync("* SEARCH 1");
                        await writer.WriteLineAsync(tag + " OK search");
                    } else if (command.Contains(" FETCH ") && command.Contains("BODY")) {
                        Interlocked.Increment(ref _bodyRequests);
                        await writer.WriteLineAsync("* 1 FETCH (UID 1 BODY[] {" + _message.Length + "}");
                        await stream.WriteAsync(_message, 0, _message.Length, _stop.Token);
                        await writer.WriteLineAsync(")");
                        await writer.WriteLineAsync(tag + " OK fetched");
                    } else if (command.Contains(" FETCH ")) {
                        await writer.WriteLineAsync("* 1 FETCH (UID 1" + (_includeSize ? " RFC822.SIZE " + (_honestSize ? _message.Length : 128) : "") + ")");
                        await writer.WriteLineAsync(tag + " OK size");
                    } else if (command.Contains(" LOGOUT")) {
                        await writer.WriteLineAsync("* BYE closed");
                        await writer.WriteLineAsync(tag + " OK logout");
                        return;
                    } else {
                        throw new InvalidOperationException("Unsupported fixture command: " + command);
                    }
                }
            } catch (Exception ex) when (ex is IOException || ex is SocketException || ex is OperationCanceledException || ex is ObjectDisposedException) {
                // The bounded client aborts an oversized literal; disposing the fixture also closes blocked reads.
            }
        }

        public async ValueTask DisposeAsync() {
            _stop.Cancel();
            _peer?.Dispose();
            _listener.Stop();
            try { await _server; } finally { _stop.Dispose(); }
        }
    }
}
