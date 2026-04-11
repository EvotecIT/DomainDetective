using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Tests whether SMTP servers accept a recipient at a target domain.
/// </summary>
public class SmtpRecipientAcceptanceAnalysis : IHasAssessments
{
    /// <summary>Result of a single SMTP recipient acceptance probe.</summary>
    public sealed class RecipientAcceptanceResult
    {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; init; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; init; }
        /// <summary>Gets or sets the recipient value.</summary>
        public string Recipient { get; init; } = string.Empty;
        /// <summary>Gets or sets the accepted value.</summary>
        public bool Accepted { get; init; }
        /// <summary>Gets or sets the mail from status code value.</summary>
        public int? MailFromStatusCode { get; init; }
        /// <summary>Gets or sets the recipient status code value.</summary>
        public int? RecipientStatusCode { get; init; }
        /// <summary>Gets or sets the mail from response value.</summary>
        public string MailFromResponse { get; init; } = string.Empty;
        /// <summary>Gets or sets the recipient response value.</summary>
        public string RecipientResponse { get; init; } = string.Empty;
    }

    /// <summary>Subject under analysis.</summary>
    public string? Subject { get; set; }

    /// <summary>Per-host probe results.</summary>
    public Dictionary<string, RecipientAcceptanceResult> ServerResults { get; } = new();

    /// <summary>Connection timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>MAIL FROM address used during the probe.</summary>
    public string SenderAddress { get; set; } = "probe@example.com";

    /// <summary>Local EHLO name used during the probe.</summary>
    public string HeloHost { get; set; } = "example.com";

    /// <summary>Structured assessments captured during the analysis.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Checks a set of SMTP servers for recipient acceptance.</summary>
    public async Task AnalyzeServers(
        IEnumerable<string> hosts,
        int port,
        string recipientAddress,
        InternalLogger logger,
        CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        foreach (var host in hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SMTPRCPT", target: $"{host}:{port}");
            var result = await ProbeRecipientAsync(host, port, recipientAddress, logger, cancellationToken).ConfigureAwait(false);
            ServerResults[$"{host}:{port}"] = result;
        }
    }

    private async Task<RecipientAcceptanceResult> ProbeRecipientAsync(
        string host,
        int port,
        string recipientAddress,
        InternalLogger logger,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);

        try
        {
            await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
            using NetworkStream network = client.GetStream();
            using var reader = new StreamReader(network);
            using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

            await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);
            timeoutCts.Token.ThrowIfCancellationRequested();

            await writer.WriteLineAsync("EHLO " + HeloHost).WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
            await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);

            timeoutCts.Token.ThrowIfCancellationRequested();
            await writer.WriteLineAsync("MAIL FROM:<" + SenderAddress + ">").WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
            var mailFromResponse = await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);

            timeoutCts.Token.ThrowIfCancellationRequested();
            await writer.WriteLineAsync("RCPT TO:<" + recipientAddress + ">").WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
            var recipientResponse = await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);

            try
            {
                await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
                await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
                await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // ignore
            }

            var mailFromCode = ParseStatusCode(mailFromResponse);
            var recipientCode = ParseStatusCode(recipientResponse);
            var accepted = mailFromCode is >= 200 and < 300
                && (recipientCode is >= 200 and < 300 || recipientCode == 251 || recipientCode == 252);

            if (accepted)
            {
                logger?.WriteWarningCode("SMTPRCPT_ACCEPTED", "SMTP server {0}:{1} accepted recipient {2}", host, port, recipientAddress);
            }
            else
            {
                logger?.WriteInformationCode("SMTPRCPT_REJECTED", "SMTP server {0}:{1} rejected recipient {2}", host, port, recipientAddress);
            }

            return new RecipientAcceptanceResult
            {
                Host = host,
                Port = port,
                Recipient = recipientAddress,
                Accepted = accepted,
                MailFromStatusCode = mailFromCode,
                RecipientStatusCode = recipientCode,
                MailFromResponse = mailFromResponse ?? string.Empty,
                RecipientResponse = recipientResponse ?? string.Empty
            };
        }
        catch (TaskCanceledException ex)
        {
            throw new OperationCanceledException(ex.Message, ex, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger?.WriteInformationCode("SMTPRCPT_FAILED", "SMTP recipient probe failed for {0}:{1} - {2}", host, port, ex.Message);
            return new RecipientAcceptanceResult
            {
                Host = host,
                Port = port,
                Recipient = recipientAddress
            };
        }
    }

    private static int? ParseStatusCode(string? response)
    {
        if (response != null && response.Length >= 3 && int.TryParse(response.Substring(0, 3), out var code))
        {
            return code;
        }

        return null;
    }

    private static async Task<string?> ReadResponseAsync(StreamReader reader, CancellationToken token)
    {
        string? line = await reader.ReadLineAsync().WaitWithCancellation(token).ConfigureAwait(false);
        if (line == null)
        {
            return null;
        }

        var code = line.Length >= 3 ? line.Substring(0, 3) : string.Empty;
        var lastLine = line;
        while (line.Length >= 4 && line[3] == '-')
        {
            line = await reader.ReadLineAsync().WaitWithCancellation(token).ConfigureAwait(false);
            if (line == null)
            {
                break;
            }

            if (line.StartsWith(code, StringComparison.Ordinal))
            {
                lastLine = line;
            }
            else
            {
                break;
            }
        }

        return lastLine;
    }
}
