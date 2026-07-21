using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective;

/// <summary>Describes the outcome of an open-recursion probe.</summary>
public enum OpenResolverStatus {
    /// <summary>No probe outcome is available.</summary>
    Unknown,
    /// <summary>The server returned a recursive answer for an unrelated public name.</summary>
    Open,
    /// <summary>The server returned a valid response that refused or did not offer recursion.</summary>
    Closed,
    /// <summary>The probe failed or returned an invalid or inconclusive response.</summary>
    Failed
}

/// <summary>Checks if DNS servers allow recursive queries.</summary>
/// <para>Part of the DomainDetective project.</para>
public class OpenResolverAnalysis : IHasAssessments {
    private const string ProbeName = "example.com";

    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Legacy recursion results keyed by server and port. Consult <see cref="ServerDetails"/> to distinguish a closed resolver from a failed probe.</summary>
    public Dictionary<string, bool> ServerResults { get; private set; } = new();
    /// <summary>Detailed results keyed by server and port.</summary>
    public Dictionary<string, OpenResolverResult> ServerDetails { get; private set; } = new();
    /// <summary>Maximum wait time for each query.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    internal Func<string, int, Task<bool>>? RecursionTestOverride { get; set; }
    internal Func<string, int, CancellationToken, Task<OpenResolverResult>>? RecursionDetailOverride { get; set; }

    /// <summary>Gets assessments produced by the most recent analysis.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Tests a single server for open recursion.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "OpenResolver", target: $"{host}:{port}");
        Subject ??= $"{host}:{port}";
        Assessments.Clear();
        ServerResults.Clear();
        ServerDetails.Clear();
        var detail = await CheckRecursionDetailAsync(host, port, logger, cancellationToken);
        RecordResult(host, port, detail, logger);
    }

    /// <summary>Tests multiple servers and ports for open recursion.</summary>
    public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
        Assessments.Clear();
        ServerResults.Clear();
        ServerDetails.Clear();
        foreach (var host in hosts) {
            foreach (var port in ports) {
                cancellationToken.ThrowIfCancellationRequested();
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "OpenResolver", target: $"{host}:{port}");
                var detail = await CheckRecursionDetailAsync(host, port, logger, cancellationToken);
                RecordResult(host, port, detail, logger);
            }
        }
    }

    private void RecordResult(string host, int port, OpenResolverResult detail, InternalLogger logger) {
        var key = $"{host}:{port}";
        ServerResults[key] = detail.Status == OpenResolverStatus.Open;
        ServerDetails[key] = detail;
        LogAnomalies(detail, logger, host, port);
        switch (detail.Status) {
            case OpenResolverStatus.Open:
                logger.WriteWarningCode(OpenResolverCodes.RecursionDetected, "Recursion allowed on {0}:{1}", host, port);
                break;
            case OpenResolverStatus.Closed:
                logger.WriteInformationCode(OpenResolverCodes.RecursionClosed, "Recursion disabled on {0}:{1}", host, port);
                break;
            default:
                logger.WriteWarningCode(OpenResolverCodes.CheckFailed, "Open resolver check failed for {0}:{1} - {2}", host, port, detail.Error ?? "the response was inconclusive");
                break;
        }
    }

    private static void LogAnomalies(OpenResolverResult detail, InternalLogger logger, string host, int port) {
        if (detail.Status == OpenResolverStatus.Open || detail.Status == OpenResolverStatus.Closed) {
            return;
        }

        var reasons = new List<string>();
        if (detail.TransactionIdMatches == false) reasons.Add("transaction ID mismatch");
        if (detail.QuestionMatches == false) reasons.Add("question mismatch");
        if (detail.QrBitSet == false) reasons.Add("QR=0");
        if (detail.Opcode.HasValue && detail.Opcode.Value != 0) reasons.Add($"opcode={detail.Opcode.Value}");
        if (detail.TcBitSet == true) reasons.Add("TC=1");
        if (reasons.Count > 0) {
            logger.WriteInformationCode(OpenResolverCodes.AnomalousResponse, "Anomalous DNS response from {0}:{1} ({2})", host, port, string.Join(", ", reasons));
        }
    }

    private async Task<OpenResolverResult> CheckRecursionDetailAsync(string server, int port, InternalLogger logger, CancellationToken token) {
        if (RecursionDetailOverride != null) {
            return await RecursionDetailOverride(server, port, token);
        }
        if (RecursionTestOverride != null) {
            var open = await RecursionTestOverride(server, port);
            return new OpenResolverResult {
                Host = server,
                Port = port,
                Status = open ? OpenResolverStatus.Open : OpenResolverStatus.Closed,
                IsOpenResolver = open
            };
        }

        var query = new DnsMessage(ProbeName, DnsRecordType.A, new DnsMessageOptions(
            RecursionDesired: true));
        ushort id = query.TransactionId;
        try {
            var sw = Stopwatch.StartNew();
            DnsWireQueryResult result = await DnsWireQueryClient.QueryUdpAsync(
                server,
                port,
                query,
                checked((int)Math.Max(1, Math.Min(Timeout.TotalMilliseconds, int.MaxValue))),
                useTcpFallback: false,
                cancellationToken: token).ConfigureAwait(false);
            sw.Stop();
            return ParseResponse(server, port, id, result.ResponseMessage, (int)sw.ElapsedMilliseconds);
        } catch (TimeoutException) {
            return Failed(server, port, "The DNS query timed out.");
        } catch (OperationCanceledException) {
            throw;
        } catch (Exception ex) {
            return Failed(server, port, ex.Message);
        }
    }

    internal static OpenResolverResult ParseResponse(string server, int port, ushort expectedId, byte[] data, int elapsedMilliseconds = 0) {
        var detail = new OpenResolverResult {
            Host = server,
            Port = port,
            ResponseBytes = data?.Length ?? 0,
            QueryTimeMs = elapsedMilliseconds,
            SourceEndpointValidated = true
        };
        if (!DnsWireMessageParser.TryParseHeader(data, out DnsWireHeaderInfo header)) {
            detail.Status = OpenResolverStatus.Failed;
            detail.Error = "The DNS response header was truncated.";
            return detail;
        }

        detail.TransactionIdMatches = header.TransactionId == expectedId;
        detail.QrBitSet = header.IsResponse;
        detail.Opcode = header.OperationCode;
        detail.AaBitSet = header.IsAuthoritativeAnswer;
        detail.TcBitSet = header.IsTruncated;
        detail.RdBitSet = header.IsRecursionDesired;
        detail.RaBitSet = header.IsRecursionAvailable;
        detail.AdBitSet = header.AuthenticData;
        detail.CdBitSet = header.CheckingDisabled;
        detail.Rcode = (int)header.ResponseCode;
        detail.QdCount = header.QuestionCount;
        detail.AnCount = header.AnswerCount;
        detail.NsCount = header.AuthorityCount;
        detail.ArCount = header.AdditionalCount;
        detail.QuestionMatches = header.QuestionCount == 1 &&
            DnsWireMessageParser.TryParseQuestion(data, 0, out DnsWireQuestionInfo question) &&
            string.Equals(question.Name, ProbeName, StringComparison.OrdinalIgnoreCase) &&
            question.Type == (ushort)DnsRecordType.A && question.Class == 1;

        if (detail.TransactionIdMatches != true || detail.QrBitSet != true || detail.Opcode != 0 || detail.QuestionMatches != true || detail.TcBitSet == true) {
            detail.Status = OpenResolverStatus.Failed;
            detail.Error = "The DNS response did not match the recursion probe.";
        } else if (detail.RaBitSet == true && detail.Rcode == 0 && detail.AnCount > 0) {
            detail.Status = OpenResolverStatus.Open;
            detail.IsOpenResolver = true;
        } else if (detail.RaBitSet == false || detail.Rcode == 5) {
            detail.Status = OpenResolverStatus.Closed;
        } else {
            detail.Status = OpenResolverStatus.Failed;
            detail.Error = $"The DNS response was inconclusive (RA={detail.RaBitSet}, RCODE={detail.Rcode}, ANCOUNT={detail.AnCount}).";
        }
        return detail;
    }

    private static OpenResolverResult Failed(string server, int port, string error) => new() {
        Host = server,
        Port = port,
        Status = OpenResolverStatus.Failed,
        Error = error
    };
}

/// <summary>Detailed open resolver test result.</summary>
public sealed class OpenResolverResult {
    /// <summary>Gets or sets the host value.</summary>
    public string Host { get; set; } = null!;
    /// <summary>Gets or sets the port value.</summary>
    public int Port { get; set; }
    /// <summary>Gets or sets the probe status.</summary>
    public OpenResolverStatus Status { get; set; }
    /// <summary>Gets or sets whether the server was proven to be an open resolver.</summary>
    public bool IsOpenResolver { get; set; }
    /// <summary>Gets or sets the failure or inconclusive-result reason.</summary>
    public string? Error { get; set; }
    /// <summary>Gets or sets whether the connected UDP socket validated the response source endpoint.</summary>
    public bool? SourceEndpointValidated { get; set; }
    /// <summary>Gets or sets whether the transaction ID matched the query.</summary>
    public bool? TransactionIdMatches { get; set; }
    /// <summary>Gets or sets whether the response question matched the probe.</summary>
    public bool? QuestionMatches { get; set; }
    /// <summary>Gets or sets the RA bit.</summary>
    public bool? RaBitSet { get; set; }
    /// <summary>Gets or sets the RCODE.</summary>
    public int? Rcode { get; set; }
    /// <summary>Gets or sets the response size.</summary>
    public int? ResponseBytes { get; set; }
    /// <summary>Gets or sets the query time.</summary>
    public int? QueryTimeMs { get; set; }
    /// <summary>Gets or sets the QR bit.</summary>
    public bool? QrBitSet { get; set; }
    /// <summary>Gets or sets the AA bit.</summary>
    public bool? AaBitSet { get; set; }
    /// <summary>Gets or sets the TC bit.</summary>
    public bool? TcBitSet { get; set; }
    /// <summary>Gets or sets the RD bit.</summary>
    public bool? RdBitSet { get; set; }
    /// <summary>Gets or sets the AD bit.</summary>
    public bool? AdBitSet { get; set; }
    /// <summary>Gets or sets the CD bit.</summary>
    public bool? CdBitSet { get; set; }
    /// <summary>Gets or sets the DNS opcode.</summary>
    public int? Opcode { get; set; }
    /// <summary>Gets or sets QDCOUNT.</summary>
    public int? QdCount { get; set; }
    /// <summary>Gets or sets ANCOUNT.</summary>
    public int? AnCount { get; set; }
    /// <summary>Gets or sets NSCOUNT.</summary>
    public int? NsCount { get; set; }
    /// <summary>Gets or sets ARCOUNT.</summary>
    public int? ArCount { get; set; }
}
