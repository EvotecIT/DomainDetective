using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Reflection;

namespace DomainDetective.Tests;

[Collection("Performance proxy environment")]
public class TestScopedWebEndpoints {
    [Theory]
    [InlineData(false, false, "[fe80::1%12]", 8080)]
    [InlineData(false, true, "[fe80::1%12]", 8080)]
    [InlineData(true, false, "[fe80::1%12]", 8443)]
    [InlineData(true, true, "[fe80::1%12]", 8443)]
    [InlineData(true, false, "[fe80::1%12]", 80)]
    [InlineData(true, true, "[fe80::1%12]", 80)]
    [InlineData(true, false, "example.com", 80)]
    [InlineData(true, true, "example.com", 80)]
    [InlineData(true, false, "192.0.2.1", 80)]
    public async Task DirectHttpChecksRetainScopeAndExplicitPort(bool https, bool customized, string authority, int port) {
        using var health = new DomainHealthCheck();
        var requests = new ConcurrentBag<Uri>();
        health.HttpAnalysis.HttpHandlerFactory = () => new RecordingHandler(requests);
        var options = new HttpRequestOptions();
        if (https) {
            if (customized) { await health.VerifyWebsiteHttps($"{authority}:{port}", options); }
            else { await health.VerifyWebsiteHttps($"{authority}:{port}"); }
        } else {
            if (customized) { await health.VerifyPlainHttp($"{authority}:{port}", options); }
            else { await health.VerifyPlainHttp($"{authority}:{port}"); }
        }
        var uri = Assert.Single(requests);
        Assert.Equal(new Uri($"http://{authority}").IdnHost, uri.IdnHost);
        Assert.Equal(port, uri.Port);
        Assert.Equal($"{(https ? "https" : "http")}://{authority}:{port}", health.HttpAnalysis.Subject);
    }

    [Theory]
    [InlineData("https://[fe80::1%12]/path?q=1", "fe80::1%12", 8443)]
    [InlineData("https://[fe80::1%12]/path?q=1", "fe80::1%12", 443)]
    [InlineData("https://[::ffff:192.0.2.1]/path?q=1", "::ffff:192.0.2.1", 8443)]
    [InlineData("https://bücher.example/path?q=1", "xn--bcher-kva.example", 8443)]
    public async Task CertificateAndProtocolProbesRetainEndpointIdentity(string url, string expectedHost, int port) {
        string[] names = { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        try {
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, null); }
            var resolved = new ConcurrentBag<string>();
            using var analysis = new CertificateAnalysis {
                PreferTlsHandshakeOnlyProbe = true, CaptureExtendedMetadata = false, CaptureTlsDetails = false,
                OutboundAddressResolver = (host, _) => {
                    resolved.Add(host);
                    return Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
                }
            };
            await analysis.AnalyzeUrl(url, port, new InternalLogger());
            var target = new Uri(analysis.Url!);
            Assert.Equal(expectedHost, target.IdnHost);
            Assert.Equal(port, target.Port);
            Assert.Contains($":{port}/path?q=1", analysis.Url!);
            Assert.Equal("/path?q=1", target.PathAndQuery);
            Assert.Equal(expectedHost, Assert.Single(resolved));
            while (resolved.TryTake(out _)) { }
            var probe = typeof(CertificateAnalysis).GetMethod("ProbeProtocolSupport", BindingFlags.NonPublic | BindingFlags.Instance)!;
            using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await (Task)probe.Invoke(analysis, new object[] { target, port, new InternalLogger(), guard.Token })!;
            Assert.Equal(4, resolved.Count);
            Assert.All(resolved, host => Assert.Equal(expectedHost, host));
        } finally {
            foreach (var name in names) { Environment.SetEnvironmentVariable(name, previous[name]); }
        }
    }

    [Fact]
    public async Task RedirectToAnotherScopeRetainsEvidenceAndDropsOriginCustomization() {
        using var health = new DomainHealthCheck();
        var handler = new ScopedRedirectHandler();
        health.HttpAnalysis.HttpHandlerFactory = () => handler;
        var options = new HttpRequestOptions();
        options.Headers["X-Fixture"] = "origin-only";
        await health.VerifyWebsiteHttps("[fe80::1%12]:8443", options);
        Assert.True(health.HttpAnalysis.IsReachable);
        Assert.Equal(new[] { "fe80::1%12", "fe80::1%13" }, handler.Hosts);
        Assert.Equal(new[] { true, false }, handler.Customized);
        Assert.Equal(new[] { "https://[fe80::1%12]:8443/", "https://[fe80::1%13]:8443/" }, health.HttpAnalysis.VisitedUrls);
        using var certificate = new CertificateAnalysis();
        typeof(CertificateAnalysis).GetMethod("CaptureRedirectTarget", BindingFlags.NonPublic | BindingFlags.Instance)!
            .Invoke(certificate, new object[] { new Uri("https://[fe80::1%13]:8443/"), new Uri("https://[fe80::1%12]:8443/") });
        Assert.Equal("[fe80::1%13]", Assert.Single(certificate.RedirectTargets));
    }

    private sealed class ScopedRedirectHandler : HttpMessageHandler {
        public List<string> Hosts { get; } = new();
        public List<bool> Customized { get; } = new();
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            Hosts.Add(request.RequestUri!.IdnHost);
            Customized.Add(request.Headers.Contains("X-Fixture"));
            var response = new HttpResponseMessage(Hosts.Count == 1 ? HttpStatusCode.Redirect : HttpStatusCode.OK) {
                RequestMessage = request, Content = new StringContent("<html></html>")
            };
            if (Hosts.Count == 1) { response.Headers.Location = new Uri("https://[fe80::1%13]:8443/"); }
            return Task.FromResult(response);
        }
    }

    private sealed class RecordingHandler(ConcurrentBag<Uri> requests) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            requests.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                RequestMessage = request, Content = new StringContent("<html></html>")
            });
        }
    }
}
