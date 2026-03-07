using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestCtLogIntegration
{
    public TestCtLogIntegration()
    {
        CtLogAggregator.ResetSharedStateForTests();
    }

    [Fact]
    public async Task CertificateAnalysisExposesEntries()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[{\"id\":5}]") };
        await analysis.AnalyzeCertificate(cert);
        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Contains("override", analysis.CtDiscoverySources);
        Assert.Empty(analysis.CtTemplateFormatErrors);
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

    [Fact]
    public async Task CertificateAnalysisCensysCredentialsFallBackToEnvironment()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "{\"result\":{\"fingerprint\":\"abc\"}}")
        });
        var previousId = System.Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_ID");
        var previousSecret = System.Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_SECRET");
        try
        {
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_ID", "env-id");
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_SECRET", "env-secret");
            var analysis = new CertificateAnalysis
            {
                SkipRevocation = true,
                EnableCensysCtSource = true,
                CensysCtApiUrlTemplate = "https://search.censys.io/api/v2/certificates/{0}"
            };
            analysis.CtLogApiTemplates.Clear();
            analysis.CtLogs.HttpHandlerFactory = () => handler;
            analysis.CtLogs.MinimumRequestSpacing = System.TimeSpan.Zero;
            analysis.CtLogs.RetryDelay = System.TimeSpan.Zero;

            await analysis.AnalyzeCertificate(cert);

            Assert.True(analysis.PresentInCtLogs);
            Assert.Contains("censys", analysis.CtDiscoverySources);
            Assert.Single(handler.RequestUrls);
            Assert.StartsWith("https://search.censys.io/api/v2/certificates/", handler.RequestUrls[0], System.StringComparison.Ordinal);
            Assert.Single(handler.AuthorizationHeaders);
            var expectedAuthorization = "Basic " + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("env-id:env-secret"));
            Assert.Equal(expectedAuthorization, handler.AuthorizationHeaders[0]);
        }
        finally
        {
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_ID", previousId);
            System.Environment.SetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_SECRET", previousSecret);
        }
    }

    [Fact]
    public async Task CertificateAnalysisKeepsTemplateEvidenceWhenCensysFails()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var handler = new SequenceHandler(new[]
        {
            CreateJsonResponse(HttpStatusCode.OK, "[{\"id\":11}]"),
            CreateJsonResponse(HttpStatusCode.ServiceUnavailable, string.Empty)
        });
        var analysis = new CertificateAnalysis
        {
            SkipRevocation = true,
            EnableCensysCtSource = true,
            CensysApiId = "id",
            CensysApiSecret = "secret",
            CensysCtApiUrlTemplate = "https://search.censys.io/api/v2/certificates/{0}"
        };
        analysis.CtLogApiTemplates.Clear();
        analysis.CtLogApiTemplates.Add("https://crt.sh/?sha256={0}&output=json");
        analysis.CtLogs.HttpHandlerFactory = () => handler;
        analysis.CtLogs.MinimumRequestSpacing = System.TimeSpan.Zero;
        analysis.CtLogs.RetryDelay = System.TimeSpan.Zero;
        analysis.CtLogs.MaxAttemptsPerRequest = 1;

        await analysis.AnalyzeCertificate(cert);

        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Equal(11, analysis.CtLogEntries[0].GetProperty("id").GetInt32());
        Assert.Contains("crt.sh", analysis.CtDiscoverySources);
        Assert.Contains("censys", analysis.CtDiscoverySources);
        Assert.Equal(2, handler.RequestUrls.Count);
    }

    [Fact]
    public async Task CertificateAnalysisExposesCtTemplateFormatErrors()
    {
        var cert = new X509Certificate2("Data/wildcard.pem");
        var analysis = new CertificateAnalysis
        {
            SkipRevocation = true,
            EnableCensysCtSource = true,
            CensysApiId = "id",
            CensysApiSecret = "secret",
            CensysCtApiUrlTemplate = string.Empty
        };
        analysis.CtLogApiTemplates.Clear();

        await analysis.AnalyzeCertificate(cert);

        Assert.False(analysis.PresentInCtLogs);
        Assert.Empty(analysis.CtDiscoverySources);
        Assert.Contains(analysis.CtTemplateFormatErrors, error =>
            error.IndexOf("CensysApiUrlTemplate", System.StringComparison.OrdinalIgnoreCase) >= 0);
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
        private readonly ConcurrentQueue<string> _authorizationHeaders = new();

        public SequenceHandler(IEnumerable<HttpResponseMessage> responses)
        {
            _responses = new ConcurrentQueue<HttpResponseMessage>(responses);
        }

        public IReadOnlyList<string> RequestUrls => _requestUrls.ToList();
        public IReadOnlyList<string> AuthorizationHeaders => _authorizationHeaders.ToList();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _requestUrls.Enqueue(request.RequestUri?.ToString() ?? string.Empty);
            if (request.Headers.TryGetValues("Authorization", out var authorization))
            {
                _authorizationHeaders.Enqueue(authorization.FirstOrDefault() ?? string.Empty);
            }
            if (_responses.TryDequeue(out var response))
            {
                return Task.FromResult(response);
            }

            return Task.FromResult(CreateJsonResponse(HttpStatusCode.OK, "[]"));
        }
    }
}
