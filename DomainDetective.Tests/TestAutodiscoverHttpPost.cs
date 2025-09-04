using DomainDetective;
using RichardSzalay.MockHttp;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestAutodiscoverHttpPost {
    [Fact]
    public async Task UsesPostOnHttpsWhenGetNotSufficient() {
        var mock = new MockHttpMessageHandler();
        // First GET to HTTPS endpoint returns 405 (common for endpoints requiring POST)
        mock.When(HttpMethod.Get, "https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.MethodNotAllowed);
        // POST returns XML
        mock.When(HttpMethod.Post, "https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => mock };
        await analysis.Analyze("example.com", new InternalLogger());

        Assert.Single(analysis.Endpoints);
        var result = analysis.Endpoints[0];
        Assert.Equal(AutodiscoverMethod.AutodiscoverSubdomainHttps, result.Method);
        Assert.Equal(200, result.StatusCode);
        Assert.True(result.XmlValid);
    }
}

