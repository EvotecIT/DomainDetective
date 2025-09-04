using System;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Provides TLS metadata for HTTPS endpoints.
/// </summary>
public class TlsAnalysis : IHasAssessments
{
    public string? Subject { get; set; }
    public Dictionary<string, TlsProbe.Result> ServerResults { get; } = new();
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "TLS", target: $"{host}:{port}");
        var result = await TlsProbe.ProbeAsync(host, port, cancellationToken);
        ServerResults[$"{host}:{port}"] = result;
        if (result.Protocol == SslProtocols.Tls13 || result.Protocol == SslProtocols.Tls12)
        {
            logger?.WriteInformationCode(TlsCodes.StrongProtocol, "Strong TLS protocol negotiated on {0}:{1} - {2}", host, port, result.Protocol);
        }
        var suite = result.CipherSuite ?? string.Empty;
        if (!string.IsNullOrEmpty(suite))
        {
            var up = suite.ToUpperInvariant();
            if (up.Contains("ECDHE", StringComparison.Ordinal) || up.Contains("DHE", StringComparison.Ordinal))
            {
                logger?.WriteInformationCode(TlsCodes.PfsCipher, "Forward secrecy cipher negotiated on {0}:{1} - {2}", host, port, suite);
            }
        }
    }

    public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        foreach (var host in hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await AnalyzeServer(host, port, logger, cancellationToken);
        }
    }
}

