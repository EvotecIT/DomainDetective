using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverHttpListenerResults {
    [Fact]
    public async Task FirstUrlReturnsProperOrdering() {
        const int port = 45678;
        var startUrl = $"https://autodiscover.localhost:{port}/autodiscover/autodiscover.xml";

        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                if (string.Equals(request.RequestUri?.AbsoluteUri, startUrl, StringComparison.OrdinalIgnoreCase)) {
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
        Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
        Assert.Equal(startUrl, result.Url);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
        Assert.Equal(new[] { result.Url! }, result.RedirectChain);
    }

    [Fact]
    public async Task RedirectResultContainsEntireChain() {
        const int port = 56789;
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
        Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
        Assert.Contains(startUrl, result.RedirectChain!);
        Assert.Contains(redirectUrl, result.RedirectChain!);
    }

    [Fact]
    public async Task EndpointOrderConsistentWhenAllFail() {
        const int port = 60000;
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, cancellationToken) => {
                throw new HttpRequestException("No server");
            })
        };

        await analysis.Analyze($"localhost:{port}", new InternalLogger());

        Assert.Equal(5, analysis.Endpoints.Count);
        string[] expectedUrls = {
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
