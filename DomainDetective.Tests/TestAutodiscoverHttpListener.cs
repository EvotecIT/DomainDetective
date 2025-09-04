using System;
using System.Net;
using System.Net.Http;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using DomainDetective;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestAutodiscoverHttpListener {
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
        public async Task FirstUrlSucceeds() {
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
            Assert.Equal(200, result.StatusCode);
            Assert.True(result.XmlValid);
            Assert.Equal($"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml", result.Url);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
        public async Task RedirectIsFollowed() {
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
            Assert.Equal(2, result.RedirectChain?.Count);
            Assert.Equal(200, result.StatusCode);
            Assert.True(result.XmlValid);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task AllEndpointsFailWhenNoServer() {
        var port = PortHelper.GetFreePort();
        PortHelper.ReleasePort(port);
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new RewriteHandler(new HttpClientHandler { AllowAutoRedirect = false })
        };
        await analysis.Analyze($"localhost:{port}", new InternalLogger());
        Assert.Equal(5, analysis.Endpoints.Count);
        Assert.Equal(
            new[] {
                AutodiscoverMethod.AutodiscoverSubdomainHttps,
                AutodiscoverMethod.RootDomainHttps,
                AutodiscoverMethod.HttpRedirect,
                AutodiscoverMethod.HttpRedirect,
                AutodiscoverMethod.OutlookV2Json
            },
            analysis.Endpoints.Select(e => e.Method).ToArray());
        Assert.All(analysis.Endpoints, e => Assert.Equal(0, e.StatusCode));
    }
}
