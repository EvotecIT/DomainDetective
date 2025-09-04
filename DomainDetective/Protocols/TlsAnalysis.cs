using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Provides TLS metadata for HTTPS endpoints.
/// </summary>
public class TlsAnalysis : IHasAssessments, IDisposable
{
    public string? Subject { get; set; }
    public Dictionary<string, TlsProbe.Result> ServerResults { get; } = new();
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public int MaxConcurrency { get; set; } = Environment.ProcessorCount;
    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    private static bool IsStrongProtocol(SslProtocols protocol)
    {
#if NET8_0_OR_GREATER
        return protocol == SslProtocols.Tls12 || protocol == SslProtocols.Tls13;
#else
        return protocol == SslProtocols.Tls12;
#endif
    }

    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "TLS", target: $"{host}:{port}");
        var result = await TlsProbe.ProbeAsync(host, port, Timeout, cancellationToken);
        ServerResults[$"{host}:{port}"] = result;
        if (IsStrongProtocol(result.Protocol))
        {
            logger?.WriteInformationCode(TlsCodes.StrongProtocol, "Strong TLS protocol negotiated on {0}:{1} - {2}", host, port, result.Protocol);
        }
        var suite = result.CipherSuite ?? string.Empty;
        if (!string.IsNullOrEmpty(suite))
        {
            if (suite.IndexOf("ECDHE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                suite.IndexOf("DHE", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                logger?.WriteInformationCode(TlsCodes.PfsCipher, "Forward secrecy cipher negotiated on {0}:{1} - {2}", host, port, suite);
            }
        }
    }

    public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var gate = new SemaphoreSlim(Math.Max(1, MaxConcurrency));
        var tasks = hosts.Select(async host =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await AnalyzeServer(host, port, logger, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public void Dispose()
    {
        foreach (var r in ServerResults.Values)
        {
            r.Dispose();
        }
    }
}

