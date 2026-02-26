using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestCtLogIntegration
{
    [Fact]
    public async Task CertificateAnalysisExposesEntries()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[{\"id\":5}]") };
        await analysis.AnalyzeCertificate(cert);
        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Contains("override", analysis.CtDiscoverySources);
        Assert.Equal(5, analysis.CtLogEntries[0].GetProperty("id").GetInt32());
    }

    [Fact]
    public async Task CertificateAnalysisUsesShodanConnectorAndParsesMatches()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"matches\":[{\"id\":10}]}")
        });
        var analysis = new CertificateAnalysis
        {
            SkipRevocation = true,
            EnableShodanCtSource = true,
            ShodanApiKey = "local-key"
        };
        analysis.CtLogApiTemplates.Clear();
        analysis.CtLogs.HttpHandlerFactory = () => handler;
        analysis.CtLogs.MinimumRequestSpacing = System.TimeSpan.Zero;
        analysis.CtLogs.RetryDelay = System.TimeSpan.Zero;

        await analysis.AnalyzeCertificate(cert);

        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Equal(10, analysis.CtLogEntries[0].GetProperty("id").GetInt32());
        Assert.Contains("shodan", analysis.CtDiscoverySources);
    }

    [Fact]
    public async Task CertificateAnalysisShodanKeyFallsBackToEnvironment()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"matches\":[]}")
        });
        var previous = System.Environment.GetEnvironmentVariable("DOMAINDETECTIVE_SHODAN_API_KEY");
        try
        {
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_SHODAN_API_KEY", "env-key+value");
            var analysis = new CertificateAnalysis
            {
                SkipRevocation = true,
                EnableShodanCtSource = true
            };
            analysis.CtLogApiTemplates.Clear();
            analysis.CtLogs.HttpHandlerFactory = () => handler;
            analysis.CtLogs.MinimumRequestSpacing = System.TimeSpan.Zero;
            analysis.CtLogs.RetryDelay = System.TimeSpan.Zero;

            await analysis.AnalyzeCertificate(cert);

            Assert.False(analysis.PresentInCtLogs);
            Assert.Contains("shodan", analysis.CtDiscoverySources);
            Assert.Single(handler.RequestUrls);
            Assert.Contains("key=env-key%2Bvalue", handler.RequestUrls[0], System.StringComparison.Ordinal);
        }
        finally
        {
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_SHODAN_API_KEY", previous);
        }
    }

    private static HttpResponseMessage CreateJsonResponse(HttpStatusCode statusCode, string json)
    {
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(json)
        };
    }

    private sealed class SequenceHandler : HttpMessageHandler
    {
        private readonly ConcurrentQueue<HttpResponseMessage> _responses;
        private readonly ConcurrentQueue<string> _requestUrls = new();

        public SequenceHandler(IEnumerable<HttpResponseMessage> responses)
        {
            _responses = new ConcurrentQueue<HttpResponseMessage>(responses);
        }

        public IReadOnlyList<string> RequestUrls => _requestUrls.ToList();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _requestUrls.Enqueue(request.RequestUri?.ToString() ?? string.Empty);
            if (_responses.TryDequeue(out var response))
            {
                return Task.FromResult(response);
            }

            return Task.FromResult(CreateJsonResponse(HttpStatusCode.OK, "[]"));
        }
    }
}
