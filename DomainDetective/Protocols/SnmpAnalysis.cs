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

    internal static readonly byte[] Probe = new byte[]
    {
        0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
    };

    internal static async Task<bool> ProbeAsync(string host, int port, TimeSpan timeout, InternalLogger? logger, CancellationToken token)
    {
        try
        {
            IPAddress address;
            if (IPAddress.TryParse(host, out var parsedAddress) && parsedAddress != null) {
                address = parsedAddress;
            } else {
                address = (await Dns.GetHostAddressesAsync(host).ConfigureAwait(false)).First();
            }

            using var udp = new UdpClient(address.AddressFamily);
            udp.Client.SendTimeout = (int)timeout.TotalMilliseconds;
            udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;
            udp.Connect(address, port);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);
#if NET8_0_OR_GREATER
            await udp.SendAsync(Probe, cts.Token).ConfigureAwait(false);
            var result = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
#else
            await udp.SendAsync(Probe, Probe.Length).WaitWithCancellation(cts.Token).ConfigureAwait(false);
            var result = await udp.ReceiveAsync().WaitWithCancellation(cts.Token).ConfigureAwait(false);
#endif
            return result.Buffer.Length > 0;
        }
        catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException)
        {
            logger?.WriteVerbose("SNMP query failed for {0}:{1} - {2}", host, port, ex.Message);
            return false;
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
