using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverHttpListener {
    [Fact]
    public async Task FirstUrlSucceeds() {
        const int port = 12345;
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                var response = new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = new StringContent("<Autodiscover></Autodiscover>")
                };
                return response;
            })
        };

        await analysis.Analyze($"localhost:{port}", new InternalLogger());

        Assert.Single(analysis.Endpoints);
        var result = analysis.Endpoints[0];
        Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
        Assert.Equal($"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml", result.Url);
    }

    [Fact]
    public async Task RedirectIsFollowed() {
        const int port = 23456;
        var startUrl = $"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml";
        var redirectUrl = $"https://localhost:{port}/autodiscover/autodiscover.xml";

        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (string.Equals(request.RequestUri?.AbsoluteUri, startUrl, StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.Found);
                    response.Headers.Location = new Uri(redirectUrl);
                    return response;
                }

                if (string.Equals(request.RequestUri?.AbsoluteUri, redirectUrl, StringComparison.OrdinalIgnoreCase)) {
                    var response = new HttpResponseMessage(HttpStatusCode.OK) {
                        Content = new StringContent("<Autodiscover></Autodiscover>")
                    };
                    return response;
                }

                throw new HttpRequestException("Unexpected URL: " + request.RequestUri);
            })
        };

        await analysis.Analyze($"localhost:{port}", new InternalLogger());

        Assert.Single(analysis.Endpoints);
        var result = analysis.Endpoints[0];
        Assert.Equal(2, result.RedirectChain?.Count);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
    }

    [Fact]
    public async Task AllEndpointsFailWhenNoServer() {
        const int port = 34567;
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                throw new HttpRequestException("No server");
            })
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
