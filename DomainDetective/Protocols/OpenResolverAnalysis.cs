using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Checks if DNS servers allow recursive queries.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class OpenResolverAnalysis : IHasAssessments {
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Recursion results keyed by server and port.</summary>
    public Dictionary<string, bool> ServerResults { get; private set; } = new();

    /// <summary>Detailed results keyed by server and port.</summary>
    public Dictionary<string, OpenResolverResult> ServerDetails { get; private set; } = new();

    /// <summary>Maximum wait time for each query.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    internal Func<string, int, Task<bool>>? RecursionTestOverride { get; set; }

    /// <summary>Tests a single server for open recursion.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Analyzes server.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "OpenResolver", target: $"{host}:{port}");
        Subject ??= $"{host}:{port}";
        Assessments.Clear();
        ServerResults.Clear();
        ServerDetails.Clear();
        var detail = await CheckRecursionDetailAsync(host, port, logger, cancellationToken);
        ServerResults[$"{host}:{port}"] = detail.IsOpenResolver;
        ServerDetails[$"{host}:{port}"] = detail;
        LogAnomalies(detail, logger, host, port);
        if (detail.IsOpenResolver) {
            logger.WriteWarningCode(OpenResolverCodes.RecursionDetected, "Recursion allowed on {0}:{1}", host, port);
        } else {
            logger.WriteInformationCode(OpenResolverCodes.RecursionClosed, "Recursion disabled on {0}:{1}", host, port);
        }
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
                ServerResults[$"{host}:{port}"] = detail.IsOpenResolver;
                ServerDetails[$"{host}:{port}"] = detail;
                LogAnomalies(detail, logger, host, port);
                if (detail.IsOpenResolver) {
                    logger.WriteWarningCode(OpenResolverCodes.RecursionDetected, "Recursion allowed on {0}:{1}", host, port);
                } else {
                    logger.WriteInformationCode(OpenResolverCodes.RecursionClosed, "Recursion disabled on {0}:{1}", host, port);
                }
            }
        }
    }

    private static void LogAnomalies(OpenResolverResult detail, InternalLogger logger, string host, int port)
    {
        try
        {
            if (detail == null || detail.IsOpenResolver)
            {
                return;
            }

            var reasons = new List<string>();
            if (detail.QrBitSet == false)
            {
                reasons.Add("QR=0");
            }
            if (detail.Opcode.HasValue && detail.Opcode.Value != 0)
            {
                reasons.Add($"opcode={detail.Opcode.Value}");
            }
            if (detail.TcBitSet == true)
            {
                reasons.Add("TC=1");
            }
            if (detail.RaBitSet == true && detail.Rcode.HasValue && detail.Rcode.Value != 0)
            {
                reasons.Add($"RA=1 rcode={detail.Rcode.Value}");
            }
            if (detail.Rcode.HasValue && detail.Rcode.Value != 0 && detail.Rcode.Value != 5)
            {
                reasons.Add($"rcode={detail.Rcode.Value}");
            }

            if (reasons.Count == 0)
            {
                return;
            }

            logger.WriteInformationCode(OpenResolverCodes.AnomalousResponse, "Anomalous DNS response from {0}:{1} ({2})", host, port, string.Join(", ", reasons));
        }
        catch
        {
        }
    }

    private static byte[] EncodeDomainName(string name) {
        var parts = name.TrimEnd('.').Split('.');
        using var ms = new System.IO.MemoryStream();
        foreach (var part in parts) {
            var bytes = System.Text.Encoding.ASCII.GetBytes(part);
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
        header[2] = 0x01; // recursion desired
        header[5] = 0x01; // qdcount
        var qname = EncodeDomainName(domain);
        var query = new byte[header.Length + qname.Length + 4];
        Buffer.BlockCopy(header, 0, query, 0, header.Length);
        Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
        var offset = header.Length + qname.Length;
        query[offset] = 0x00;
        query[offset + 1] = 0x01; // A
        query[offset + 2] = 0x00;
        query[offset + 3] = 0x01; // IN
        return query;
    }

    private async Task<OpenResolverResult> CheckRecursionDetailAsync(string server, int port, InternalLogger logger, CancellationToken token) {
        if (RecursionTestOverride != null) {
            var open = await RecursionTestOverride(server, port);
            return new OpenResolverResult {
                Host = server,
                Port = port,
                IsOpenResolver = open,
            };
        }

        try {
            using var udp = new UdpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
            var id = Helpers.DnsQueryIdGenerator.NextUShort();
            var query = BuildQuery("example.com", id);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await udp.SendAsync(query, query.Length, server, port).WaitWithCancellation(cts.Token);
            var result = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
            sw.Stop();
            var data = result.Buffer;
            ushort flags = data.Length > 3 ? (ushort)((data[2] << 8) | data[3]) : (ushort)0;
            bool qr = (flags & 0x8000) != 0;
            int opcode = (flags >> 11) & 0x0F;
            bool aa = (flags & 0x0400) != 0;
            bool tc = (flags & 0x0200) != 0;
            bool rd = (flags & 0x0100) != 0;
            bool ra = (flags & 0x0080) != 0;
            bool ad = (flags & 0x0020) != 0;
            bool cd = (flags & 0x0010) != 0;
            int rcode = data.Length > 3 ? (flags & 0x000F) : -1;
            int qd = data.Length > 5 ? ((data[4] << 8) | data[5]) : -1;
            int an = data.Length > 7 ? ((data[6] << 8) | data[7]) : -1;
            int ns = data.Length > 9 ? ((data[8] << 8) | data[9]) : -1;
            int ar = data.Length > 11 ? ((data[10] << 8) | data[11]) : -1;
            bool open = data.Length > 3 && ra && rcode == 0;
            return new OpenResolverResult {
                Host = server,
                Port = port,
                IsOpenResolver = open,
                RaBitSet = ra,
                Rcode = rcode,
                ResponseBytes = data.Length,
                QueryTimeMs = (int)sw.ElapsedMilliseconds,
                QrBitSet = qr,
                AaBitSet = aa,
                TcBitSet = tc,
                RdBitSet = rd,
                AdBitSet = ad,
                CdBitSet = cd,
                Opcode = opcode,
                QdCount = qd,
                AnCount = an,
                NsCount = ns,
                ArCount = ar
            };
        } catch (TaskCanceledException ex) {
            throw new OperationCanceledException(ex.Message, ex, token);
        } catch (Exception ex) {
            logger.WriteWarningCode(OpenResolverCodes.CheckFailed, "Open resolver check failed for {0}:{1} - {2}", server, port, ex.Message);
            return new OpenResolverResult {
                Host = server,
                Port = port,
                IsOpenResolver = false
            };
        }
    }
}

/// <summary>Detailed open resolver test result.</summary>
public sealed class OpenResolverResult {
    /// <summary>Gets or sets the host value.</summary>
    public string Host { get; set; } = null!;
    /// <summary>Gets or sets the port value.</summary>
    public int Port { get; set; }
    /// <summary>Gets or sets the is open resolver value.</summary>
    public bool IsOpenResolver { get; set; }
    /// <summary>Gets or sets the ra bit set value.</summary>
    public bool? RaBitSet { get; set; }
    /// <summary>Gets or sets the rcode value.</summary>
    public int? Rcode { get; set; }
    /// <summary>Gets or sets the response bytes value.</summary>
    public int? ResponseBytes { get; set; }
    /// <summary>Gets or sets the query time ms value.</summary>
    public int? QueryTimeMs { get; set; }
    /// <summary>Gets or sets the qr bit set value.</summary>
    public bool? QrBitSet { get; set; }
    /// <summary>Gets or sets the aa bit set value.</summary>
    public bool? AaBitSet { get; set; }
    /// <summary>Gets or sets the tc bit set value.</summary>
    public bool? TcBitSet { get; set; }
    /// <summary>Gets or sets the rd bit set value.</summary>
    public bool? RdBitSet { get; set; }
    /// <summary>Gets or sets the ad bit set value.</summary>
    public bool? AdBitSet { get; set; }
    /// <summary>Gets or sets the cd bit set value.</summary>
    public bool? CdBitSet { get; set; }
    /// <summary>Gets or sets the opcode value.</summary>
    public int? Opcode { get; set; }
    /// <summary>Gets or sets the qd count value.</summary>
    public int? QdCount { get; set; }
    /// <summary>Gets or sets the an count value.</summary>
    public int? AnCount { get; set; }
    /// <summary>Gets or sets the ns count value.</summary>
    public int? NsCount { get; set; }
    /// <summary>Gets or sets the ar count value.</summary>
    public int? ArCount { get; set; }
}
