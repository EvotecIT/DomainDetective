using DomainDetective;
using RichardSzalay.MockHttp;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestAutodiscoverHints {
    [Fact]
    public async Task AttemptsCnameAndSrvTargetsWhenProvided() {
        var mock = new MockHttpMessageHandler();
        // Make the first four attempts fail
        mock.When("https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("https://example.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("http://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("http://example.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);

        // JSON v2 attempt returns 404 so flow can continue to CNAME target
        mock.When("https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/example.com?Protocol=AutodiscoverV1")
            .Respond(HttpStatusCode.NotFound);

        // CNAME target succeeds
        mock.When("https://autodiscover.outlook.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => mock,
            CnameTarget = "autodiscover.outlook.com"
        };

        await analysis.Analyze("example.com", new InternalLogger());

        Assert.Equal(6, analysis.Endpoints.Count);
        Assert.Equal(AutodiscoverMethod.CnameTargetHttps, analysis.Endpoints.Last().Method);
        Assert.True(analysis.Endpoints.Last().XmlValid);
    }

    [Fact]
    public async Task AttemptsSrvTargetWhenProvided() {
        var mock = new MockHttpMessageHandler();
        // Fail the first base attempts
        mock.When("https://autodiscover.example.net/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("https://example.net/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("http://autodiscover.example.net/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);
        mock.When("http://example.net/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.NotFound);

        // JSON v2 attempt returns 404 so flow can continue to SRV target
        mock.When("https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/example.net?Protocol=AutodiscoverV1")
            .Respond(HttpStatusCode.NotFound);

        // SRV target: GET returns XML directly on a distinct host to avoid clashes with earlier rules
        mock.When(HttpMethod.Get, "https://autodiscover-srv.example.net:443/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => mock,
            SrvTarget = "autodiscover-srv.example.net",
            SrvPort = 443
        };
        await analysis.Analyze("example.net", new InternalLogger());

        Assert.Equal(6, analysis.Endpoints.Count);
        var srv = analysis.Endpoints.Single(e => e.Method == AutodiscoverMethod.SrvTargetHttps);
        Assert.True(srv.XmlValid);
        Assert.Equal(200, srv.StatusCode);
    }
}
