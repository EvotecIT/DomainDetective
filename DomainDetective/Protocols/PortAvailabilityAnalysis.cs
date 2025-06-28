using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
///     Attempts TCP connections to common service ports and records latency.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class PortAvailabilityAnalysis
{
    /// <summary>Represents the result of a single port check.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public class PortResult
    {
        /// <summary>Gets a value indicating whether the connection succeeded.</summary>
        public bool Success { get; init; }
        /// <summary>Gets the time taken to establish the connection.</summary>
        public TimeSpan Latency { get; init; }
    }

    /// <summary>Results for each host and port.</summary>
    public Dictionary<string, PortResult> ServerResults { get; } = new();
    /// <summary>Maximum time to wait for a connection.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Checks a single host and port.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        ServerResults[$"{host}:{port}"] = await CheckPort(host, port, logger, cancellationToken);
    }

    /// <summary>Checks multiple hosts and ports.</summary>
    public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        foreach (var host in hosts)
        {
            foreach (var port in ports)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ServerResults[$"{host}:{port}"] = await CheckPort(host, port, logger, cancellationToken);
            }
        }
    }

    private async Task<PortResult> CheckPort(string host, int port, InternalLogger logger, CancellationToken token)
    {
        using var client = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(Timeout);
        var sw = Stopwatch.StartNew();
        try
        {
#if NET6_0_OR_GREATER
            await client.ConnectAsync(host, port, cts.Token);
#else
            await client.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
#endif
            sw.Stop();
            return new PortResult { Success = true, Latency = sw.Elapsed };
        }
        catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
        {
            sw.Stop();
            logger?.WriteVerbose("Port {0}:{1} unreachable - {2}", host, port, ex.Message);
            return new PortResult { Success = false, Latency = sw.Elapsed };
        }
    }
}
