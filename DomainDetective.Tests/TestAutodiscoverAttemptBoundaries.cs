using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverAttemptBoundaries {
    internal const string RecognizedError = "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"><Response><Error><ErrorCode>600</ErrorCode><Message>Invalid Request</Message></Error></Response></Autodiscover>";

    [Theory]
    [InlineData("<Autodiscover xmlns=\"urn:unrelated\"><Bogus/></Autodiscover>")]
    [InlineData("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"><Bogus/></Autodiscover>")]
    [InlineData("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"><Response><Account><AccountType>email</AccountType><Action>settings</Action></Account></Response></Autodiscover>")]
    [InlineData("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\"><Response><Account><AccountType>email</AccountType><Action>redirectAddr</Action><RedirectAddr>invalid</RedirectAddr></Account></Response></Autodiscover>")]
    public async Task UnrecognizedResponseDoesNotStopValidFallback(string invalid) {
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new Handler((request, _) => Task.FromResult(Response(
                request.RequestUri!.Host.StartsWith("autodiscover.", StringComparison.Ordinal) ? invalid : RecognizedError)))
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(2, analysis.Endpoints.Count);
        Assert.Equal("example.test", analysis.Endpoints[1].FinalHost);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == AutodiscoverCodes.EndpointDiscovered && item.Target == "https://autodiscover.example.test/autodiscover/autodiscover.xml");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerCancellationStopsXmlAndJsonStages(bool json) {
        using var caller = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new Handler(async (request, token) => {
                Interlocked.Increment(ref calls);
                if (json && request.RequestUri!.Host != "autodiscover-s.outlook.com") return new HttpResponseMessage(HttpStatusCode.NotFound);
                entered.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, token);
                return Response(RecognizedError);
            })
        };
        Task run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000)));
        int beforeCancel = calls; caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(beforeCancel, calls);
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == AutodiscoverCodes.CheckFailed);
    }

    [Fact]
    public async Task EndpointTimeoutContinuesToValidFallback() {
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            Timeout = TimeSpan.FromMilliseconds(500), AnalysisTimeout = TimeSpan.FromSeconds(10),
            HttpHandlerFactory = () => new Handler(async (_, token) => {
                if (Interlocked.Increment(ref calls) == 1) await Task.Delay(System.Threading.Timeout.Infinite, token);
                return Response(RecognizedError);
            })
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.False(analysis.BudgetExhausted);
        Assert.Equal(2, calls);
        Assert.NotNull(analysis.Endpoints[0].Error);
        Assert.False(analysis.Endpoints[0].DiscoverySucceeded);
        Assert.True(analysis.Endpoints[1].DiscoverySucceeded);
        Assert.Equal("request", Assert.Single(analysis.Endpoints[0].Requests).FailureStage);
    }

    [Fact]
    public async Task OverallDeadlineStopsRemainingFallbacks() {
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            Timeout = TimeSpan.FromSeconds(10), AnalysisTimeout = TimeSpan.FromMilliseconds(500),
            HttpHandlerFactory = () => new Handler(async (_, token) => {
                Interlocked.Increment(ref calls); await Task.Delay(System.Threading.Timeout.Infinite, token);
                return Response(RecognizedError);
            })
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.True(analysis.BudgetExhausted);
        Assert.InRange(calls, 0, 1);
        Assert.DoesNotContain(analysis.Endpoints, endpoint => endpoint.DiscoverySucceeded);
    }

    [Theory]
    [InlineData("http")]
    [InlineData("https")]
    public async Task RecognizedAnonymousErrorConfirmsServiceWithoutMailboxClaims(string schemaScheme) {
        string body = RecognizedError.Replace("http://schemas", schemaScheme + "://schemas");
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(Response(body))) };
        await analysis.Analyze("example.test", new InternalLogger());
        var endpoint = Assert.Single(analysis.Endpoints);
        Assert.True(endpoint.DiscoverySucceeded); Assert.Equal("error", endpoint.ServiceResponseType);
        Assert.Single(endpoint.Requests);
    }

    [Fact]
    public async Task PostPayloadKeepsRequestNamespaceAndEscapesEmail() {
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            EmailForPost = "user+tag@example.test",
            HttpHandlerFactory = () => new Handler(async (request, _) => {
                Interlocked.Increment(ref calls);
                if (request.Method == HttpMethod.Get) return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed);
                var doc = System.Xml.Linq.XDocument.Parse(await request.Content!.ReadAsStringAsync());
                System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006";
                Assert.Equal(analysisEmail, doc.Root!.Element(ns + "Request")!.Element(ns + "EMailAddress")!.Value);
                return Response(RecognizedError);
            })
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(2, calls); Assert.True(Assert.Single(analysis.Endpoints).DiscoverySucceeded);
    }
    private const string analysisEmail = "user+tag@example.test";

    private static HttpResponseMessage Response(string content) => new(HttpStatusCode.OK) { Content = new StringContent(content) };
    private sealed class Handler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        public Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => _send(request, token);
    }
}
