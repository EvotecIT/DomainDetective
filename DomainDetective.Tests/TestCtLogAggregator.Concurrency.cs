using System.Net;
using System.Net.Http;

namespace DomainDetective.Tests;

public partial class TestCtLogAggregator {
    [Fact]
    public async Task CancelingOneCtWaiterPreservesOtherWaiterAndSingleRequest() {
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        int active = 0;
        Func<HttpMessageHandler> factory = () => new AsyncHandler(async (_, token) => {
            Interlocked.Increment(ref calls);
            Interlocked.Increment(ref active);
            entered.TrySetResult(true);
            try { await release.Task.WaitWithCancellation(token); }
            finally { Interlocked.Decrement(ref active); }
            return Json("[{\"id\":42}]");
        });
        string url = "https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}";
        var first = CreateConcurrentAggregator(factory, url);
        var second = CreateConcurrentAggregator(factory, url);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        var firstTask = first.QueryAsync("fingerprint", canceled.Token);
        await entered.Task.WaitWithCancellation(guard.Token);
        var secondTask = second.QueryAsync("fingerprint", guard.Token);
        try {
            canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstTask);
            Assert.Equal(1, calls);
            Assert.Equal(1, active);
            release.TrySetResult(true);
            Assert.Equal(42, Assert.Single(await secondTask).GetProperty("id").GetInt32());
            Assert.Equal(0, active);
        } finally {
            release.TrySetResult(true);
            guard.Cancel();
            try { await Task.WhenAll(firstTask, secondTask); } catch (OperationCanceledException) { }
        }
    }

    [Theory]
    [InlineData("[]", HttpStatusCode.OK, 1)]
    [InlineData("not json", HttpStatusCode.OK, 2)]
    [InlineData("[]", HttpStatusCode.ServiceUnavailable, 2)]
    public async Task OnlyCompletedCtResponsesIncludingEmptyAreCached(string body, HttpStatusCode status, int expectedCalls) {
        int calls = 0;
        Func<HttpMessageHandler> factory = () => new AsyncHandler((_, _) => {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
        });
        var aggregator = CreateConcurrentAggregator(factory, "https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}");
        Assert.Empty(await aggregator.QueryAsync("empty"));
        Assert.Empty(await aggregator.QueryAsync("empty"));
        Assert.Equal(expectedCalls, calls);
        Assert.Equal(expectedCalls == 1, aggregator.LastQueryComplete);
    }

    [Fact]
    public async Task LastCanceledCtWaiterDrainsProducerBeforeReturning() {
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool drained = false;
        Func<HttpMessageHandler> factory = () => new AsyncHandler(async (_, token) => {
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { drained = true; }
            return Json("[]");
        });
        var aggregator = CreateConcurrentAggregator(factory, "https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var task = aggregator.QueryAsync("canceled", cancellation.Token);
        await entered.Task.WaitWithCancellation(cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        Assert.True(drained);
    }

    private static CtLogAggregator CreateConcurrentAggregator(Func<HttpMessageHandler> factory, string url) {
        var aggregator = new CtLogAggregator { HttpHandlerFactory = factory, MaxAttemptsPerRequest = 1 };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add(url);
        return aggregator;
    }

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };
    private sealed class AsyncHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }
}
