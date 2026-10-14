using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class MailTlsAnalysis {
    private static bool UsesDirectTls(MailProtocol protocol, int port) =>
        protocol == MailProtocol.Imap && port == 993 || protocol == MailProtocol.Pop3 && port == 995;

    /// <summary>Performs the mail exchange required before a TLS handshake without closing the transport.</summary>
    private static async Task<(bool Advertised, bool Ready)> NegotiateStartTlsAsync(MailProtocol protocol,
        NetworkStream network, InternalLogger? logger, CancellationToken token) {
        using var reader = new StreamReader(network, Encoding.UTF8, false, 1024, leaveOpen: true);
        using var writer = new StreamWriter(network, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
        async Task<string?> ReadAsync() {
            var line = await reader.ReadLineAsync().WaitWithCancellation(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return line;
        }
        Task WriteAsync(string command) => writer.WriteLineAsync(command).WaitWithCancellation(token);

        if (await ReadAsync().ConfigureAwait(false) == null) { throw new IOException("Mail server closed before its greeting."); }
        var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        switch (protocol) {
            case MailProtocol.Smtp:
                await WriteAsync("EHLO example.test").ConfigureAwait(false);
                string? line;
                while ((line = await ReadAsync().ConfigureAwait(false)) != null) {
                    logger?.WriteVerbose("EHLO response: {0}", line);
                    if (line.StartsWith("250", StringComparison.Ordinal)) {
                        string values = line.Length > 4 ? line.Substring(4) : string.Empty;
                        foreach (var value in values.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) { capabilities.Add(value); }
                        if (!line.StartsWith("250-", StringComparison.Ordinal)) { break; }
                    } else if (line.StartsWith("4", StringComparison.Ordinal) || line.StartsWith("5", StringComparison.Ordinal)) { break; }
                }
                break;
            case MailProtocol.Imap:
                await WriteAsync("A1 CAPABILITY").ConfigureAwait(false);
                while ((line = await ReadAsync().ConfigureAwait(false)) != null) {
                    logger?.WriteVerbose("CAPABILITY response: {0}", line);
                    if (line.StartsWith("* CAPABILITY ", StringComparison.OrdinalIgnoreCase)) {
                        foreach (var value in line.Substring(13).Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) { capabilities.Add(value); }
                    } else if (line.StartsWith("A1 ", StringComparison.OrdinalIgnoreCase)) { break; }
                }
                break;
            case MailProtocol.Pop3:
                await WriteAsync("CAPA").ConfigureAwait(false);
                while ((line = await ReadAsync().ConfigureAwait(false)) != null) {
                    logger?.WriteVerbose("CAPA response: {0}", line);
                    if (line == "." || line.StartsWith("-ERR", StringComparison.OrdinalIgnoreCase)) { break; }
                    capabilities.Add(line.Trim());
                }
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(protocol));
        }

        bool advertised = capabilities.Contains(protocol == MailProtocol.Pop3 ? "STLS" : "STARTTLS");
        if (!advertised) {
            await WriteAsync(GetQuitCommand(protocol)).ConfigureAwait(false);
            await ReadAsync().ConfigureAwait(false);
            return (false, false);
        }
        await WriteAsync(protocol == MailProtocol.Imap ? "A2 STARTTLS" : protocol == MailProtocol.Pop3 ? "STLS" : "STARTTLS").ConfigureAwait(false);
        var response = await ReadAsync().ConfigureAwait(false);
        bool ready = protocol switch {
            MailProtocol.Smtp => response?.StartsWith("220", StringComparison.Ordinal) == true,
            MailProtocol.Imap => response?.StartsWith("A2 OK", StringComparison.OrdinalIgnoreCase) == true,
            MailProtocol.Pop3 => response?.StartsWith("+OK", StringComparison.OrdinalIgnoreCase) == true,
            _ => false
        };
        if (!ready) { logger?.WriteVerbose("Mail STARTTLS rejected: {0}", response); }
        return (true, ready);
    }
}
