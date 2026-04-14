using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

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
    public async Task ReadBatchAsync_WithZeroKnownTreeSize_ReturnsEmptyWithoutAdditionalSthRequest() {
        int sthCalls = 0;
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref sthCalls);
                    throw new InvalidOperationException("get-sth should not be called when KnownTreeSize is zero.");
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://ct.example.test/",
                StartIndex = 0,
                BatchSize = 16,
                KnownTreeSize = 0,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.Equal(0L, batch.TreeSize);
        Assert.Equal(0L, batch.StartIndex);
        Assert.Equal(-1L, batch.EndIndex);
        Assert.Empty(batch.Entries);
        Assert.Equal(0, sthCalls);
    }

    [Fact]
    public async Task ReadBatchAsync_WithNegativeKnownTreeSize_FallsBackToSthRequest() {
        int sthCalls = 0;
        int getEntriesCalls = 0;
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref sthCalls);
                    return Task.FromResult(CreateSuccessResponse("""{"tree_size":2}"""));
                }

                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref getEntriesCalls);
                    return Task.FromResult(CreateSuccessResponse("""{"entries":[]}"""));
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://ct.example.test/",
                StartIndex = 0,
                BatchSize = 16,
                KnownTreeSize = -1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.Equal(2L, batch.TreeSize);
        Assert.Equal(0, batch.StartIndex);
        Assert.Equal(-1, batch.EndIndex);
        Assert.Equal(1, sthCalls);
        Assert.Equal(1, getEntriesCalls);
    }

    [Fact]
    public async Task GetSignedTreeHeadAsync_ReusesCachedTreeHeadWithinTtl() {
        int sthCalls = 0;
        var client = new CtLogIngestionClient {
            SignedTreeHeadCacheDuration = TimeSpan.FromMinutes(1),
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    Interlocked.Increment(ref sthCalls);
                    return Task.FromResult(CreateSuccessResponse("""{"tree_size":42}"""));
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtSignedTreeHead first = await client.GetSignedTreeHeadAsync("https://ct.example.test/", TimeSpan.FromSeconds(5), CancellationToken.None);
        CtSignedTreeHead second = await client.GetSignedTreeHeadAsync("https://ct.example.test/", TimeSpan.FromSeconds(5), CancellationToken.None);

        Assert.Equal(42L, first.TreeSize);
        Assert.Equal(42L, second.TreeSize);
        Assert.Equal(1, sthCalls);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task GetEntriesAsync_ReturnsEmpty_ForInvertedRange() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => throw new InvalidOperationException("HTTP should not be called for an inverted range.")
        };

        IReadOnlyList<RawCtEntryPayload> entries = await client.GetEntriesAsync(
            "https://ct.example.test/",
            start: 5,
            end: 4,
            timeout: TimeSpan.FromSeconds(5),
            cancellationToken: CancellationToken.None);

        Assert.Empty(entries);
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
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
}
