using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestWebAvailabilityAnalysis {
    [Fact]
    public async Task CapturesPublicEndpointRedirectAndSignals() {
        var finalRequestHadApiKey = false;
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.AbsoluteUri.Equals("http://example.test/", StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
                    response.Headers.Location = new Uri("https://example.test/");
                    response.Headers.TryAddWithoutValidation("Server", "edge");
                    response.Headers.TryAddWithoutValidation("X-Cache", "redirect-hop");
                    return response;
                }

                finalRequestHadApiKey = request.Headers.Contains("X-Api-Key");
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
        options.Headers["X-Api-Key"] = "secret";

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("http://example.test/", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.NotNull(analysis.PublicEndpoint);
        Assert.Equal(200, analysis.PublicEndpoint!.StatusCode);
        Assert.Equal("https://example.test/", analysis.PublicEndpoint.FinalUrl);
        Assert.Equal(2, analysis.PublicEndpoint.RedirectChain.Count);
        Assert.Equal("cloudflare", analysis.PublicEndpoint.ResponseHeaders["Server"]);
        Assert.False(analysis.PublicEndpoint.ResponseHeaders.ContainsKey("X-Cache"));
        Assert.Equal("cloudflare", analysis.PublicResponseSignals["Server"]);
        Assert.Equal("abc-WAW", analysis.PublicResponseSignals["CF-Ray"]);
        Assert.Equal("DYNAMIC", analysis.PublicResponseSignals["CF-Cache-Status"]);
        Assert.Equal("request-id", analysis.PublicResponseSignals["X-GitHub-Request-Id"]);
        Assert.True(finalRequestHadApiKey);
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

    [Fact]
    public async Task DoesNotTreatCaseVariantRedirectAsLoop() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.AbsoluteUri.Equals("https://case.example/Login", StringComparison.Ordinal)) {
                    var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                    redirect.Headers.Location = new Uri("https://case.example/login");
                    return redirect;
                }

                return new HttpResponseMessage(HttpStatusCode.OK);
            })
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://case.example/Login", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.False(analysis.PublicEndpoint!.RedirectLoop);
        Assert.Equal(2, analysis.PublicEndpoint.RedirectChain.Count);
        Assert.Equal("https://case.example/login", analysis.PublicEndpoint.FinalUrl);
    }

    [Fact]
    public async Task DoesNotForwardCustomHeadersAcrossOrigins() {
        var finalRequestHadAuthorization = false;
        var finalRequestHadApiKey = false;
        var initialRequestHadAuthorization = false;
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.Host.Equals("source.example", StringComparison.OrdinalIgnoreCase)) {
                    initialRequestHadAuthorization = request.Headers.Contains("Authorization");
                    var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                    redirect.Headers.Location = new Uri("https://target.example/");
                    return redirect;
                }

                finalRequestHadAuthorization = request.Headers.Contains("Authorization");
                finalRequestHadApiKey = request.Headers.Contains("X-Api-Key");
                return new HttpResponseMessage(HttpStatusCode.OK);
            })
        };
        options.Headers["Authorization"] = "Bearer secret";
        options.Headers["X-Api-Key"] = "secret";

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://source.example/", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.True(initialRequestHadAuthorization);
        Assert.False(finalRequestHadAuthorization);
        Assert.False(finalRequestHadApiKey);
    }

    [Fact]
    public async Task UsesGetAfterSeeOtherRedirect() {
        HttpMethod? redirectedMethod = null;
        var options = new WebAvailabilityOptions {
            Method = HttpMethod.Post,
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.AbsoluteUri.Equals("https://post.example/submit", StringComparison.Ordinal)) {
                    var redirect = new HttpResponseMessage(HttpStatusCode.SeeOther);
                    redirect.Headers.Location = new Uri("https://post.example/status");
                    return redirect;
                }

                redirectedMethod = request.Method;
                return new HttpResponseMessage(HttpStatusCode.OK);
            })
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://post.example/submit", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.Equal(HttpMethod.Get, redirectedMethod);
    }

    [Fact]
    public async Task UsesGetAfterPostFoundRedirect() {
        HttpMethod? redirectedMethod = null;
        var options = new WebAvailabilityOptions {
            Method = HttpMethod.Post,
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (request.RequestUri!.AbsoluteUri.Equals("https://post.example/start", StringComparison.Ordinal)) {
                    var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                    redirect.Headers.Location = new Uri("https://post.example/complete");
                    return redirect;
                }

                redirectedMethod = request.Method;
                return new HttpResponseMessage(HttpStatusCode.OK);
            })
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://post.example/start", options);

        Assert.True(analysis.PublicEndpointAvailable);
        Assert.Equal(HttpMethod.Get, redirectedMethod);
    }

    [Fact]
    public async Task ClearsPublicEndpointBeforeCancelledAnalysis() {
        var analysis = new WebAvailabilityAnalysis();
        var successfulOptions = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => new HttpResponseMessage(HttpStatusCode.OK))
        };
        await analysis.AnalyzeAsync("https://ok.example/", successfulOptions);
        Assert.NotNull(analysis.PublicEndpoint);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var cancelledOptions = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => throw new TaskCanceledException("cancelled"))
        };

        await Assert.ThrowsAsync<TaskCanceledException>(() => analysis.AnalyzeAsync("https://cancelled.example/", cancelledOptions, cancellationToken: cts.Token));

        Assert.Null(analysis.PublicEndpoint);
    }

    [Fact]
    public async Task EmitsTlsCodeForHttpRequestExceptionHandshakeFailure() {
        var options = new WebAvailabilityOptions {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) =>
                throw new HttpRequestException("TLS failed", new AuthenticationException("bad certificate")))
        };

        var analysis = new WebAvailabilityAnalysis();
        await analysis.AnalyzeAsync("https://tls.example/", options);

        Assert.False(analysis.PublicEndpointAvailable);
        Assert.Equal(WebAvailabilityFailureKind.TlsHandshake, analysis.PublicEndpoint!.FailureKind);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == WebAvailabilityCodes.PublicEndpointTlsFailed);
    }

    [Fact]
    public async Task DisablesAutoRedirectOnInjectedDelegatingHttpClientHandler() {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var serverTask = Task.Run(async () => {
            for (var i = 0; i < 2; i++) {
                var ctx = await listener.GetContextAsync();
                if (ctx.Request.RawUrl == "/") {
                    ctx.Response.StatusCode = (int)HttpStatusCode.Found;
                    ctx.Response.RedirectLocation = prefix + "final";
                } else {
                    ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                }

                ctx.Response.Close();
            }
        });

        try {
            var options = new WebAvailabilityOptions {
                HttpHandlerFactory = () => new PassThroughHandler(new HttpClientHandler())
            };
            var analysis = new WebAvailabilityAnalysis();
            await analysis.AnalyzeAsync(prefix, options);

            Assert.True(analysis.PublicEndpointAvailable);
            Assert.Equal(2, analysis.PublicEndpoint!.RedirectChain.Count);
            Assert.Equal(prefix + "final", analysis.PublicEndpoint.FinalUrl);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    private static int GetFreePort() {
        return PortHelper.GetFreePort();
    }
}

internal sealed class PassThroughHandler : DelegatingHandler {
    public PassThroughHandler(HttpMessageHandler innerHandler) : base(innerHandler) {
    }
}
