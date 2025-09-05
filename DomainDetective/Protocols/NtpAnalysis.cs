using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries NTP servers for clock information.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class NtpAnalysis : IHasAssessments {
    /// <summary>Result of an NTP query.</summary>
    public class NtpResult {
        /// <summary>True when a valid reply was received.</summary>
        public bool Success { get; init; }
        /// <summary>Clock offset between server and local time.</summary>
        public TimeSpan Offset { get; init; }
        /// <summary>Server stratum value.</summary>
        public byte Stratum { get; init; }
    }

    /// <summary>Results keyed by server and port.</summary>
    public Dictionary<string, NtpResult> ServerResults { get; } = new();
    /// <summary>Timeout for UDP operations.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Structured assessments from NTP probing.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Queries a single NTP server.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger? logger, CancellationToken cancellationToken = default) {
        ServerResults.Clear();
        ServerResults[$"{host}:{port}"] = await QueryServer(host, port, logger, cancellationToken);
    }

    /// <summary>Queries a predefined NTP server.</summary>
    public Task AnalyzeServer(NtpServer server, int port, InternalLogger? logger, CancellationToken cancellationToken = default) =>
        AnalyzeServer(server.ToHost(), port, logger, cancellationToken);

    /// <summary>Queries multiple NTP servers.</summary>
    public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger? logger, CancellationToken cancellationToken = default) {
        ServerResults.Clear();
        foreach (var host in hosts) {
            cancellationToken.ThrowIfCancellationRequested();
            ServerResults[$"{host}:{port}"] = await QueryServer(host, port, logger, cancellationToken);
        }
    }

    /// <summary>Queries multiple predefined NTP servers.</summary>
    public Task AnalyzeServers(IEnumerable<NtpServer> servers, int port, InternalLogger? logger, CancellationToken cancellationToken = default) =>
        AnalyzeServers(servers.Select(s => s.ToHost()), port, logger, cancellationToken);

    private static ulong ReadUInt32(byte[] data, int offset) => ((ulong)data[offset] << 24) | ((ulong)data[offset + 1] << 16) | ((ulong)data[offset + 2] << 8) | data[offset + 3];

    private async Task<NtpResult> QueryServer(string host, int port, InternalLogger? logger, CancellationToken token) {
        using var udp = new UdpClient();
        try {
            udp.Client.SendTimeout = (int)Timeout.TotalMilliseconds;
            udp.Client.ReceiveTimeout = (int)Timeout.TotalMilliseconds;
            var request = new byte[48];
            request[0] = 0x1B; // client request
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
#if NET8_0_OR_GREATER
            await udp.SendAsync(request, host, port, cts.Token);
            var resp = await udp.ReceiveAsync(cts.Token);
#else
            await udp.SendAsync(request, request.Length, host, port).WaitWithCancellation(cts.Token);
            var resp = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
            if (resp.Buffer.Length < 48) {
                return new NtpResult { Success = false };
            }
            byte stratum = resp.Buffer[1];
            ulong sec = ReadUInt32(resp.Buffer, 40);
            ulong frac = ReadUInt32(resp.Buffer, 44);
            const ulong epoch = 2208988800UL;
            double seconds = sec - epoch + frac / 4294967296.0;
            var serverTime = DateTimeOffset.FromUnixTimeSeconds((long)(sec - epoch)).AddSeconds(frac / 4294967296.0);
            var offset = serverTime - DateTimeOffset.UtcNow;
            return new NtpResult { Success = true, Stratum = stratum, Offset = offset };
        } catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException) {
            logger?.WriteVerbose("NTP query failed for {0}:{1} - {2}", host, port, ex.Message);
            return new NtpResult { Success = false };
        }
    }
}
