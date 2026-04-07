using System.Net;
using System.Net.Http.Json;
using DomainDetective.Website.Models;
using DomainDetective.Website.Services;

namespace DomainDetective.Website.Tests;

public sealed class SiteNavigationServiceTests {
    [Fact]
    public async Task GetNavigationAsyncAllowsRetryAfterCanceledRequest() {
        var requestCount = 0;
        using var httpClient = new HttpClient(new StubHttpMessageHandler(request => {
            requestCount++;

            if (requestCount == 1) {
                throw new TaskCanceledException("Canceled");
            }

            return new HttpResponseMessage(HttpStatusCode.OK) {
                Content = JsonContent.Create(new SiteNavigationData {
                    Primary = new List<SiteNavigationItem> {
                        new() { Href = "/", Text = "Home" }
                    }
                })
            };
        })) {
            BaseAddress = new Uri("http://localhost")
        };
        var service = new SiteNavigationService(httpClient);

        var canceledResult = await service.GetNavigationAsync();
        var retryResult = await service.GetNavigationAsync();

        Assert.Null(canceledResult);
        Assert.NotNull(retryResult);
        Assert.Equal(2, requestCount);
        Assert.Single(retryResult.Primary);
    }

    [Fact]
    public async Task GetNavigationAsyncCachesSuccessfulFetchAcrossConcurrentCalls() {
        var requestCount = 0;
        using var httpClient = new HttpClient(new StubHttpMessageHandler(request => {
            Interlocked.Increment(ref requestCount);

            return new HttpResponseMessage(HttpStatusCode.OK) {
                Content = JsonContent.Create(new SiteNavigationData {
                    Primary = new List<SiteNavigationItem> {
                        new() { Href = "/", Text = "Home" }
                    }
                })
            };
        })) {
            BaseAddress = new Uri("http://localhost")
        };
        var service = new SiteNavigationService(httpClient);

        var results = await Task.WhenAll(service.GetNavigationAsync(), service.GetNavigationAsync());

        Assert.Equal(1, requestCount);
        Assert.All(results, result => Assert.NotNull(result));
        Assert.All(results, result => Assert.Single(result!.Primary));
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responseFactory;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) {
            _responseFactory = responseFactory;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            return Task.FromResult(_responseFactory(request));
        }
    }
}
