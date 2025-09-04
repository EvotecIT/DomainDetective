using DomainDetective;
using RichardSzalay.MockHttp;
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestAutodiscoverHttpAnalysis {
    [Fact]
    public async Task FollowsRedirectAndParsesXml() {
        var mock = new MockHttpMessageHandler();
        mock.When("https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond(req => {
                var resp = new HttpResponseMessage(System.Net.HttpStatusCode.Moved);
                resp.Headers.Location = new Uri("https://example.com/autodiscover/autodiscover.xml");
                return resp;
            });
        mock.When("https://example.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => mock };
        await analysis.Analyze("example.com", new InternalLogger());

        Assert.Single(analysis.Endpoints);
        var result = analysis.Endpoints[0];
        Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
        Assert.Contains("https://example.com/autodiscover/autodiscover.xml", result.RedirectChain!);
    }

    [Fact]
    public async Task FallsBackToHttpWhenHttpsFails() {
        var mock = new MockHttpMessageHandler();
        mock.When("https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond(System.Net.HttpStatusCode.NotFound);
        mock.When("https://example.com/autodiscover/autodiscover.xml")
            .Respond(System.Net.HttpStatusCode.NotFound);
        mock.When("http://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => mock };
        await analysis.Analyze("example.com", new InternalLogger());

        Assert.Equal(3, analysis.Endpoints.Count);
        Assert.Equal(AutodiscoverMethod.HttpRedirect, analysis.Endpoints[2].Method);
        Assert.True(analysis.Endpoints[2].XmlValid);
    }
}
