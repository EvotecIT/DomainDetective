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
public class PortAvailabilityAnalysis : IHasAssessments
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

    /// <summary>Structured assessments captured during checks.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Recommendations derived from <see cref="Assessments"/>.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Results for each host and port.</summary>
    public Dictionary<string, PortResult> ServerResults { get; } = new();
    /// <summary>Maximum time to wait for a connection.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
    internal Func<TcpClient> TcpClientFactory { get; set; } = static () => new TcpClient();

    internal static Dictionary<int, (string Code, string Name)> ExpectedPorts { get; } = new()
    {
        [25] = (PortAvailabilityCodes.SmtpResponding, "SMTP"),
        [80] = (PortAvailabilityCodes.HttpResponding, "HTTP"),
        [443] = (PortAvailabilityCodes.HttpsResponding, "HTTPS"),
        [465] = (PortAvailabilityCodes.SmtpsResponding, "SMTPS"),
        [587] = (PortAvailabilityCodes.SubmissionResponding, "SUBMISSION")
    };

    /// <summary>Checks a single host and port.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        Assessments.Clear();
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "PORTAVAIL", target: $"{host}:{port}");
        ServerResults[$"{host}:{port}"] = await CheckPort(host, port, logger, cancellationToken);
    }

    /// <summary>Checks multiple hosts and ports.</summary>
    public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        Assessments.Clear();
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "PORTAVAIL");
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
        using var client = TcpClientFactory();
        client.SendTimeout = (int)Timeout.TotalMilliseconds;
        client.ReceiveTimeout = (int)Timeout.TotalMilliseconds;
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
        if (ExpectedPorts.TryGetValue(port, out var svc))
        {
            logger?.WriteInformationCode(svc.Code, "{0} responded on {1}:{2}", svc.Name, host, port);
        }
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
