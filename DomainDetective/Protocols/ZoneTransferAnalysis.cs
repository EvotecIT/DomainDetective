using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Attempts AXFR queries to determine whether name servers allow unauthenticated zone transfers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class ZoneTransferAnalysis : IHasAssessments {
    /// <summary>Domain (zone) under test.</summary>
    public string? Subject { get; set; }

    /// <summary>Dictionary mapping server name to transfer allowance.</summary>
    public Dictionary<string, bool> ServerResults { get; private set; } = new();

    /// <summary>Maximum time to wait for each transfer attempt.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Checks all provided name servers for zone transfer capability.</summary>
    public async Task AnalyzeServers(string domain, IEnumerable<string> nameServers, InternalLogger logger,
        CancellationToken cancellationToken = default) {
        Subject = domain;
        ServerResults.Clear();
        foreach (string server in nameServers.Where(value => !string.IsNullOrWhiteSpace(value))) {
            cancellationToken.ThrowIfCancellationRequested();
            string nameServer = server.Trim().TrimEnd('.');
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "AXFR", target: nameServer);
            bool allowed = await AttemptZoneTransfer(domain, nameServer, logger, cancellationToken).ConfigureAwait(false);
            ServerResults[server] = allowed;
            if (allowed) {
                logger.WriteWarningCode(ZoneTransferCodes.Allowed, "AXFR allowed on {0}", nameServer);
            } else if (!Assessments.Any(assessment => assessment.Code == ZoneTransferCodes.CheckFailed &&
                                                       string.Equals(assessment.Target, nameServer, StringComparison.OrdinalIgnoreCase))) {
                logger.WriteInformationCode(ZoneTransferCodes.Restricted, "AXFR refused on {0}", nameServer);
            }
        }
    }

    private async Task<bool> AttemptZoneTransfer(string zone, string server, InternalLogger logger, CancellationToken token) {
        try {
            DnsResolverEndpoint endpoint = ParseTcpEndpoint(server);
            using ClientX client = ResolverEndpointClientFactory.CreateClient(endpoint);
            client.EndpointConfiguration.TimeOut = checked((int)Math.Max(1, Math.Min(Timeout.TotalMilliseconds, int.MaxValue)));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(Timeout);

            ZoneTransferResult[] results = await client.ZoneTransferAsync(
                zone,
                retryOnTransient: false,
                maxRetries: 1,
                retryDelayMs: 0,
                cancellationToken: timeout.Token).ConfigureAwait(false);
            return results.Any(result => result.IsOpening) && results.Any(result => result.IsClosing);
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
            return false;
        } catch (OperationCanceledException) {
            throw;
        } catch (DnsClientException exception) when (exception.Response != null &&
                                                     exception.Response.Status != DnsResponseCode.NoError) {
            return false;
        } catch (Exception exception) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "AXFR", target: server);
            logger.WriteWarningCode(ZoneTransferCodes.CheckFailed, "AXFR check failed for {0}: {1}", server, exception.Message);
            return false;
        }
    }

    private static DnsResolverEndpoint ParseTcpEndpoint(string server) {
        string target;
        if (IPAddress.TryParse(server, out IPAddress? address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) {
            target = $"tcp@[{server}]:53";
        } else if (server.StartsWith("[", StringComparison.Ordinal) && server.IndexOf("]:", StringComparison.Ordinal) >= 0) {
            target = $"tcp@{server}";
        } else {
            int separator = server.LastIndexOf(':');
            bool hasPort = separator > 0 && separator == server.IndexOf(':') &&
                           int.TryParse(server.Substring(separator + 1), out int port) && port > 0 && port <= 65535;
            target = hasPort ? $"tcp@{server}" : $"tcp@{server}:53";
        }

        DnsResolverEndpoint[] endpoints = EndpointParser.TryParseMany(new[] { target }, out IReadOnlyList<string> errors);
        if (errors.Count > 0 || endpoints.Length != 1) {
            throw new ArgumentException(errors.Count > 0 ? string.Join("; ", errors) : $"Invalid DNS server endpoint: {server}", nameof(server));
        }
        return endpoints[0];
    }
}
