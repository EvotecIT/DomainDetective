using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace DomainDetective.Tests;

public sealed class TestCtLogIngestionClient {
    private const HttpStatusCode TooManyRequestsStatusCode = (HttpStatusCode)429;

    [Fact]
    public async Task ReadBatchAsync_UsesKnownTreeSizeWithoutAdditionalSthRequest() {
        int sthCalls = 0;
        int getEntriesCalls = 0;
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref sthCalls);
                    throw new InvalidOperationException("get-sth should not be called when KnownTreeSize is provided.");
                }

                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref getEntriesCalls);
                    return Task.FromResult(CreateSuccessResponse("""
                        {
                          "entries": []
                        }
                        """));
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://ct.example.test/",
                StartIndex = 0,
                BatchSize = 16,
                KnownTreeSize = 1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.Equal(1L, batch.TreeSize);
        Assert.Equal(0L, batch.StartIndex);
        Assert.Equal(-1L, batch.EndIndex);
        Assert.Empty(batch.Entries);
        Assert.Equal(0, sthCalls);
        Assert.Equal(1, getEntriesCalls);
    }

    [Fact]
    public async Task GetTreeSizeAsync_PropagatesRetryAfterDelta_FromHttpResponse() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateFailureResponse(TooManyRequestsStatusCode, delta: TimeSpan.FromSeconds(45)))
        };

        HttpRequestException exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetTreeSizeAsync("https://ct.example.test/", TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Contains("Retry-After 45s", exception.Message, StringComparison.Ordinal);
        TimeSpan retryAfter = Assert.IsType<TimeSpan>(exception.Data["RetryAfter"]);
        Assert.Equal(TimeSpan.FromSeconds(45), retryAfter);
    }

    [Fact]
    public async Task GetTreeSizeAsync_PropagatesRetryAfterDate_FromHttpResponse() {
        DateTimeOffset retryAfterAt = DateTimeOffset.UtcNow.AddSeconds(75);
        var client = new CtLogIngestionClient {
            SendOverride = (_, _) => Task.FromResult(CreateFailureResponse(HttpStatusCode.ServiceUnavailable, date: retryAfterAt))
        };

        HttpRequestException exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetTreeSizeAsync("https://ct.example.test/", TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.Contains("Retry-After", exception.Message, StringComparison.Ordinal);
        TimeSpan retryAfter = Assert.IsType<TimeSpan>(exception.Data["RetryAfter"]);
        Assert.InRange(retryAfter, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(75));
    }

    [Fact]
    public async Task GetTreeSizeAsync_DoesNotAttachRetryAfter_WhenHeaderIsMissing() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateFailureResponse(HttpStatusCode.BadGateway))
        };

        HttpRequestException exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetTreeSizeAsync("https://ct.example.test/", TimeSpan.FromSeconds(5), CancellationToken.None));

        Assert.DoesNotContain("Retry-After", exception.Message, StringComparison.Ordinal);
        Assert.False(exception.Data.Contains("RetryAfter"));
    }

    private static HttpResponseMessage CreateFailureResponse(HttpStatusCode statusCode, TimeSpan? delta = null, DateTimeOffset? date = null) {
        var response = new HttpResponseMessage(statusCode) {
            ReasonPhrase = statusCode.ToString(),
            Content = new StringContent("{}")
        };

        if (delta.HasValue) {
            response.Headers.RetryAfter = new RetryConditionHeaderValue(delta.Value);
        } else if (date.HasValue) {
            response.Headers.RetryAfter = new RetryConditionHeaderValue(date.Value);
        }

        return response;
    }

    private static HttpResponseMessage CreateSuccessResponse(string json)
        => new(HttpStatusCode.OK) {
            Content = new StringContent(json)
        };
}
