using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Performs a basic SNMP check against a server.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class SnmpAnalysis : IHasAssessments
{
    /// <summary>Target under analysis.</summary>
    public string? Subject { get; set; }

    /// <summary>SNMP query results keyed by host and port.</summary>
    public Dictionary<string, bool> ServerResults { get; private set; } = new();

    /// <summary>Maximum wait time for each query.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    internal Func<string, int, Task<bool>>? SnmpTestOverride { get; set; }

    /// <summary>Structured assessments captured during SNMP analysis.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Tests a single server for SNMP responses.</summary>
    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SNMP", target: $"{host}:{port}");
        Subject ??= $"{host}:{port}";
        ServerResults.Clear();
        var result = await CheckSnmpAsync(host, port, logger, cancellationToken);
        ServerResults[$"{host}:{port}"] = result;
        if (result)
        {
            logger.WriteWarningCode(SnmpCodes.Responds, "SNMP responded on {0}:{1}", host, port);
        }
        else
        {
            logger.WriteInformationCode(SnmpCodes.Disabled, "SNMP disabled or secured on {0}:{1}", host, port);
        }
    }

    /// <summary>Tests multiple servers for SNMP responses.</summary>
    public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        foreach (var host in hosts)
        {
            foreach (var port in ports)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SNMP", target: $"{host}:{port}");
                var result = await CheckSnmpAsync(host, port, logger, cancellationToken);
                ServerResults[$"{host}:{port}"] = result;
                if (result)
                {
                    logger.WriteWarningCode(SnmpCodes.Responds, "SNMP responded on {0}:{1}", host, port);
                }
                else
                {
                    logger.WriteInformationCode(SnmpCodes.Disabled, "SNMP disabled or secured on {0}:{1}", host, port);
                }
            }
        }
    }

    internal static async Task<bool> ProbeAsync(string host, int port, TimeSpan timeout, InternalLogger? logger, CancellationToken token)
    {
        return (await ProbeResponseAsync(host, port, timeout, logger, token).ConfigureAwait(false)).IsSnmp;
    }

    internal static async Task<(bool Responded, bool IsSnmp)> ProbeResponseAsync(string host, int port, TimeSpan timeout, InternalLogger? logger, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        bool responded = false;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(timeout);
        try
        {
            IPAddress address;
            if (IPAddress.TryParse(host, out var parsedAddress) && parsedAddress != null) {
                address = parsedAddress;
            } else {
                address = (await Dns.GetHostAddressesAsync(host).WaitWithCancellation(cts.Token).ConfigureAwait(false)).First();
            }

            using var udp = new UdpClient(address.AddressFamily);
            udp.Connect(address, port); // Only datagrams from this endpoint can satisfy the probe.
            var random = new byte[4];
            using (var generator = System.Security.Cryptography.RandomNumberGenerator.Create()) {
                generator.GetBytes(random);
            }
            int requestId = BitConverter.ToInt32(random, 0) & int.MaxValue;
            var request = SnmpMessage.CreateRequest(requestId);
            await udp.SendAsync(request, request.Length).WaitWithCancellation(cts.Token).ConfigureAwait(false);
            while (true) {
                var result = await udp.ReceiveAsync().WaitWithCancellation(cts.Token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                responded |= result.Buffer.Length > 0;
                if (SnmpMessage.IsResponse(result.Buffer, requestId)) return (true, true);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) {
            throw;
        }
        catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
        {
            token.ThrowIfCancellationRequested();
            logger?.WriteVerbose("SNMP query failed for {0}:{1} - {2}", host, port, ex.Message);
            return (responded, false);
        }
    }

    private async Task<bool> CheckSnmpAsync(string host, int port, InternalLogger logger, CancellationToken token)
    {
        if (SnmpTestOverride != null)
        {
            return await SnmpTestOverride(host, port);
        }

        return await ProbeAsync(host, port, Timeout, logger, token);
    }
}
