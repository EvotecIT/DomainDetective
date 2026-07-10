using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

    private static byte[] EncodeDomainName(string name) {
        var parts = name.TrimEnd('.').Split('.');
        using var ms = new System.IO.MemoryStream();
        foreach (var part in parts) {
            var bytes = Encoding.ASCII.GetBytes(part);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] BuildQuery(string domain, ushort id) {
        var header = new byte[12];
        header[0] = (byte)(id >> 8);
        header[1] = (byte)id;
        header[2] = 0x01;
        header[5] = 0x01;
        var qname = EncodeDomainName(domain);
        var query = new byte[header.Length + qname.Length + 4];
        Buffer.BlockCopy(header, 0, query, 0, header.Length);
        Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
        var offset = header.Length + qname.Length;
        query[offset + 1] = 0x01;
        query[offset + 3] = 0x01;
        return query;
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

        var id = Helpers.DnsQueryIdGenerator.NextUShort();
        var query = BuildQuery(ProbeName, id);
        try {
            using var udp = new UdpClient();
            udp.Connect(server, port);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(Timeout);
            var sw = Stopwatch.StartNew();
            await udp.SendAsync(query, query.Length).WaitWithCancellation(timeout.Token);
            var received = await udp.ReceiveAsync().WaitWithCancellation(timeout.Token);
            sw.Stop();
            return ParseResponse(server, port, id, received.Buffer, (int)sw.ElapsedMilliseconds);
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
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
        if (data == null || data.Length < 12) {
            detail.Status = OpenResolverStatus.Failed;
            detail.Error = "The DNS response header was truncated.";
            return detail;
        }

        var responseId = (ushort)((data[0] << 8) | data[1]);
        var flags = (ushort)((data[2] << 8) | data[3]);
        detail.TransactionIdMatches = responseId == expectedId;
        detail.QrBitSet = (flags & 0x8000) != 0;
        detail.Opcode = (flags >> 11) & 0x0F;
        detail.AaBitSet = (flags & 0x0400) != 0;
        detail.TcBitSet = (flags & 0x0200) != 0;
        detail.RdBitSet = (flags & 0x0100) != 0;
        detail.RaBitSet = (flags & 0x0080) != 0;
        detail.AdBitSet = (flags & 0x0020) != 0;
        detail.CdBitSet = (flags & 0x0010) != 0;
        detail.Rcode = flags & 0x000F;
        detail.QdCount = ReadUInt16(data, 4);
        detail.AnCount = ReadUInt16(data, 6);
        detail.NsCount = ReadUInt16(data, 8);
        detail.ArCount = ReadUInt16(data, 10);
        detail.QuestionMatches = detail.QdCount == 1 && TryReadQuestion(data, out var name, out var type, out var queryClass)
            && string.Equals(name, ProbeName, StringComparison.OrdinalIgnoreCase) && type == 1 && queryClass == 1;

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

    private static bool TryReadQuestion(byte[] data, out string name, out int type, out int queryClass) {
        name = string.Empty;
        type = 0;
        queryClass = 0;
        var labels = new List<string>();
        var offset = 12;
        while (offset < data.Length) {
            var length = data[offset++];
            if (length == 0) break;
            if ((length & 0xC0) != 0 || length > 63 || offset + length > data.Length) return false;
            labels.Add(Encoding.ASCII.GetString(data, offset, length));
            offset += length;
        }
        if (labels.Count == 0 || offset + 4 > data.Length) return false;
        name = string.Join(".", labels);
        type = ReadUInt16(data, offset);
        queryClass = ReadUInt16(data, offset + 2);
        return true;
    }

    private static int ReadUInt16(byte[] data, int offset) => (data[offset] << 8) | data[offset + 1];

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
