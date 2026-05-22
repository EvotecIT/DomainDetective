using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestWebAvailabilityAnalysis {
    [Fact]
    public async Task CapturesPublicEndpointRedirectAndSignals() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.AbsoluteUri.Equals("http://example.test/", StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
                    response.Headers.Location = new Uri("https://example.test/");
                    response.Headers.TryAddWithoutValidation("Server", "edge");
                    return response;
                }

                var ok = new HttpResponseMessage(HttpStatusCode.OK) {
                    ReasonPhrase = "OK"
                };
                ok.Headers.TryAddWithoutValidation("Server", "cloudflare");
                ok.Headers.TryAddWithoutValidation("CF-Ray", "abc-WAW");
                ok.Headers.TryAddWithoutValidation("CF-Cache-Status", "DYNAMIC");
                ok.Headers.TryAddWithoutValidation("X-GitHub-Request-Id", "request-id");
                return ok;
            })
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("http://example.test/", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.NotNull(analysis.PublicEndpoint);
        Assert.Equal(200, analysis.PublicEndpoint!.StatusCode);
        Assert.Equal("https://example.test/", analysis.PublicEndpoint.FinalUrl);
        Assert.Equal(2, analysis.PublicEndpoint.RedirectChain.Count);
        Assert.Equal("cloudflare", analysis.PublicResponseSignals["Server"]);
        Assert.Equal("abc-WAW", analysis.PublicResponseSignals["CF-Ray"]);
        Assert.Equal("DYNAMIC", analysis.PublicResponseSignals["CF-Cache-Status"]);
        Assert.Equal("request-id", analysis.PublicResponseSignals["X-GitHub-Request-Id"]);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == WebAvailabilityCodes.PublicEndpointAvailable);
    }

    [Fact]
    public async Task DetectsPublicAvailableButOriginTlsFailure() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Headers.TryAddWithoutValidation("Server", "edge");
                return response;
            }),
            OriginTlsProbeOverride = (endpoint, timeout, cancellationToken) => Task.FromException<TlsProbe.Result>(
                new AuthenticationException("origin certificate rejected"))
        };
        options.OriginTlsEndpoints.Add(new WebOriginTlsEndpoint(IPAddress.Parse("192.0.2.10"), "example.test"));

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://example.test/", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.True(analysis.PublicAvailableButOriginTlsFailed);
        var origin = Assert.Single(analysis.OriginTlsEndpoints);
        Assert.False(origin.Success);
        Assert.Equal(CertificateFailureKind.TlsHandshake, origin.FailureKind);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == WebAvailabilityCodes.PublicAvailableOriginTlsFailed);
    }

    [Fact]
    public async Task CapturesValidOriginTlsEndpoint() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => new HttpResponseMessage(HttpStatusCode.OK)),
            OriginTlsProbeOverride = (endpoint, timeout, cancellationToken) => Task.FromResult(new TlsProbe.Result {
                Protocol = SslProtocols.Tls12,
                CipherSuite = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                CertificateSubject = "CN=example.test",
                CertificateIssuer = "CN=Test CA",
                CertificateValid = true,
                HostnameMatch = true
            })
        };
        options.OriginTlsEndpoints.Add(new WebOriginTlsEndpoint(IPAddress.Parse("192.0.2.11"), "example.test"));

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://example.test/", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.True(analysis.AnyOriginTlsEndpointAvailable);
        Assert.False(analysis.PublicAvailableButOriginTlsFailed);
        var origin = Assert.Single(analysis.OriginTlsEndpoints);
        Assert.True(origin.Success);
        Assert.Equal("CN=example.test", origin.CertificateSubject);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == WebAvailabilityCodes.OriginTlsAvailable);
    }

    [Fact]
    public async Task DetectsRedirectLoop() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var response = new HttpResponseMessage(HttpStatusCode.Found);
                response.Headers.Location = request.RequestUri;
                return response;
            })
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://loop.example/", options);

        Assert.False(analysis.PublicEndpointAvailable);
        Assert.True(analysis.PublicEndpoint!.RedirectLoop);
        Assert.Equal(WebAvailabilityFailureKind.RedirectLoop, analysis.PublicEndpoint.FailureKind);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == WebAvailabilityCodes.RedirectLoop);
    }
}
