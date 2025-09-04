using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestAutodiscoverHttpListenerResults {
    private sealed class RewriteHandler : DelegatingHandler {
        public RewriteHandler(HttpMessageHandler inner) : base(inner) { }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) {
            var uri = request.RequestUri!;
            var builder = new UriBuilder(uri) {
                Scheme = "http",
                Host = "localhost",
                Port = uri.Port
            };
            request.Headers.Host = "localhost";
            request.RequestUri = builder.Uri;
            return base.SendAsync(request, cancellationToken);
        }
    }

    [Fact]
    public async Task FirstUrlReturnsProperOrdering() {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/autodiscover/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var serverTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            ctx.Response.StatusCode = 200;
            var buffer = Encoding.UTF8.GetBytes("<Autodiscover></Autodiscover>");
            await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            ctx.Response.Close();
        });

        try {
            var analysis = new AutodiscoverHttpAnalysis {
                HttpHandlerFactory = () => new RewriteHandler(new HttpClientHandler { AllowAutoRedirect = false })
            };
            await analysis.Analyze($"localhost:{port}", new InternalLogger());
            Assert.Single(analysis.Endpoints);
            var result = analysis.Endpoints[0];
            Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
            Assert.Equal($"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml", result.Url);
            Assert.Equal(200, result.StatusCode);
            Assert.True(result.XmlValid);
            Assert.Equal(new[] { result.Url }, result.RedirectChain);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task RedirectResultContainsEntireChain() {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/autodiscover/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        var serverTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            ctx.Response.StatusCode = 302;
            ctx.Response.RedirectLocation = $"https://localhost:{port}/autodiscover/autodiscover.xml";
            ctx.Response.Close();
            ctx = await listener.GetContextAsync();
            ctx.Response.StatusCode = 200;
            var buffer = Encoding.UTF8.GetBytes("<Autodiscover></Autodiscover>");
            await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            ctx.Response.Close();
        });

        try {
            var analysis = new AutodiscoverHttpAnalysis {
                HttpHandlerFactory = () => new RewriteHandler(new HttpClientHandler { AllowAutoRedirect = false })
            };
            await analysis.Analyze($"localhost:{port}", new InternalLogger());
            Assert.Single(analysis.Endpoints);
            var result = analysis.Endpoints[0];
            Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
            Assert.Equal(200, result.StatusCode);
            Assert.True(result.XmlValid);
            Assert.Contains($"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml", result.RedirectChain!);
            Assert.Contains($"https://localhost:{port}/autodiscover/autodiscover.xml", result.RedirectChain!);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task EndpointOrderConsistentWhenAllFail() {
        var port = PortHelper.GetFreePort();
        PortHelper.ReleasePort(port);
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new RewriteHandler(new HttpClientHandler { AllowAutoRedirect = false })
        };
        await analysis.Analyze($"localhost:{port}", new InternalLogger());
        Assert.Equal(5, analysis.Endpoints.Count);
        string?[] expectedUrls = {
            $"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml",
            $"https://localhost:{port}/autodiscover/autodiscover.xml",
            $"http://autodiscover.localhost:{port}/autodiscover/autodiscover.xml",
            $"http://localhost:{port}/autodiscover/autodiscover.xml",
            $"https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/localhost:{port}?Protocol=AutodiscoverV1"
        };
        Assert.Equal(expectedUrls, analysis.Endpoints.Select(e => e.Url).ToArray());
        Assert.Equal(
            new[] {
                AutodiscoverMethod.AutodiscoverSubdomainHttps,
                AutodiscoverMethod.RootDomainHttps,
                AutodiscoverMethod.HttpRedirect,
                AutodiscoverMethod.HttpRedirect,
                AutodiscoverMethod.OutlookV2Json
            },
            analysis.Endpoints.Select(e => e.Method).ToArray());
        foreach (var result in analysis.Endpoints) {
            Assert.Equal(0, result.StatusCode);
            Assert.False(result.XmlValid);
            Assert.NotNull(result.RedirectChain);
            Assert.Single(result.RedirectChain!);
            Assert.Equal(result.Url, result.RedirectChain![0]);
        }
    }
}
