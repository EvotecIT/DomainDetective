using DomainDetective;
using RichardSzalay.MockHttp;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestAutodiscoverJsonV2 {
    [Fact]
    public async Task OutlookV2JsonReturnsEndpointUrl_AndFollowUpPostSucceeds() {
        var mock = new MockHttpMessageHandler();
        // Fail base attempts
        mock.When("https://autodiscover.example.org/autodiscover/autodiscover.xml").Respond(HttpStatusCode.NotFound);
        mock.When("https://example.org/autodiscover/autodiscover.xml").Respond(HttpStatusCode.NotFound);
        mock.When("http://autodiscover.example.org/autodiscover/autodiscover.xml").Respond(HttpStatusCode.NotFound);
        mock.When("http://example.org/autodiscover/autodiscover.xml").Respond(HttpStatusCode.NotFound);

        // JSON v2 discovery success
        var jsonUrl = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/example.org?Protocol=AutodiscoverV1";
        mock.When(HttpMethod.Get, jsonUrl)
            .Respond("application/json", "{ \"Protocol\": \"AutodiscoverV1\", \"Url\": \"https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml\" }");

        // Follow-up POST to discovered URL: GET returns 405 then POST returns XML
        mock.When(HttpMethod.Get, "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml")
            .Respond(HttpStatusCode.MethodNotAllowed);
        mock.When(HttpMethod.Post, "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");

        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => mock };
        await analysis.Analyze("example.org", new InternalLogger());

        // Debug: print methods seen
        System.Console.WriteLine(string.Join(", ", analysis.Endpoints.Select(e => e.Method.ToString())));

        Assert.True(analysis.Endpoints.Any(e => e.Method == AutodiscoverMethod.OutlookV2Json));
        Assert.True(analysis.Endpoints.Any(e => e.Method == AutodiscoverMethod.OutlookV2JsonPost));
        var json = analysis.Endpoints.First(e => e.Method == AutodiscoverMethod.OutlookV2Json);
        var post = analysis.Endpoints.First(e => e.Method == AutodiscoverMethod.OutlookV2JsonPost);
        Assert.Equal(AutodiscoverMethod.OutlookV2Json, json.Method);
        Assert.True(json.JsonValid);
        Assert.Equal("https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml", json.JsonEndpointUrl);
        Assert.Equal(AutodiscoverMethod.OutlookV2JsonPost, post.Method);
        Assert.True(post.XmlValid);
    }
}
