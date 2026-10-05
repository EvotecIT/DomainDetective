using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverFeedbackBoundaries {
    [Fact]
    public async Task OneEndpointOutcomeProducesOneAssessmentPerCode() {
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((_, _) => Response(TestAutodiscoverAttemptBoundaries.RecognizedError)) };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Single(analysis.Assessments, item => item.Code == AutodiscoverCodes.XmlValid);
        Assert.Single(analysis.Assessments, item => item.Code == AutodiscoverCodes.EndpointDiscovered);
        Assert.All(analysis.Assessments, item => Assert.Equal(Assert.Single(analysis.Endpoints).Url, item.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyEscapedJsonStillRequiresXmlConfirmation(bool escapedHost) {
        string url = escapedHost ? "https://" + @"\\u006dail.example.test/autodiscover/autodiscover.xml" : "https://mail.example.test/autodiscover/autodiscover.xml";
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((request, _) => {
            if (request.RequestUri!.Host == "autodiscover-s.outlook.com") return Response("{\\\"Url\\\":\\\"" + url + "\\\"}");
            if (request.RequestUri!.Host == "mail.example.test") return Response(TestAutodiscoverAttemptBoundaries.RecognizedError);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }) };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Contains(analysis.Endpoints, item => item.JsonValid);
        Assert.Equal("mail.example.test", analysis.Endpoints.Last().FinalHost);
        Assert.True(analysis.Endpoints.Last().DiscoverySucceeded);
    }

    [Fact]
    public async Task EmptyPostRetainsGetBodyDiagnostics() {
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((request, _) => {
            if (request.RequestUri!.Host == "example.test") return Response(TestAutodiscoverAttemptBoundaries.RecognizedError);
            if (request.Method == HttpMethod.Post) return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed);
            var response = Response("<html>captive portal</html>");
            response.Content.Headers.ContentType!.MediaType = "text/html";
            return response;
        }) };
        await analysis.Analyze("example.test", new InternalLogger());
        var first = analysis.Endpoints.First();
        Assert.Equal(405, first.StatusCode);
        Assert.Contains("captive portal", first.ContentSnippet);
        Assert.Equal("text/html", first.ContentType);
        Assert.True(first.ContentLooksHtml);
        Assert.Equal(2, first.Requests.Count);
    }

    [Fact]
    public async Task UnsupportedEncodingDoesNotAbortTheFlow() {
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((_, _) => {
            var response = Response(TestAutodiscoverAttemptBoundaries.RecognizedError);
            response.Content.Headers.ContentType!.CharSet = "utf-7";
            return response;
        }) };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.True(Assert.Single(analysis.Endpoints).DiscoverySucceeded);
    }

    private static HttpResponseMessage Response(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };
    private sealed class Handler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _send;
        internal Handler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Task.FromResult(_send(request, token));
    }
}
