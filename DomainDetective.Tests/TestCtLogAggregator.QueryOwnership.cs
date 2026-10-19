using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public partial class TestCtLogAggregator {
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OlderQueryCompletionDoesNotReplaceNewerQueryDiagnostics(bool newerComplete) {
        var oldStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseOld = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var aggregator = new CtLogAggregator {
            QueryOverride = async fingerprint => {
                if (fingerprint == "old") {
                    oldStarted.TrySetResult(true);
                    await releaseOld.Task;
                    return newerComplete ? "invalid" : "[{\"id\":1}]";
                }
                return newerComplete ? "[{\"id\":2}]" : "invalid";
            }
        };
        var older = aggregator.QueryWithResultAsync("old");
        CtLogQueryResult? newer = null;
        try {
            using var guard = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(10));
            await oldStarted.Task.WaitWithCancellation(guard.Token);
            newer = await aggregator.QueryWithResultAsync("new");
        } finally {
            releaseOld.TrySetResult(true);
            await older;
        }
        Assert.Equal(newerComplete, aggregator.LastQueryComplete);
        Assert.Equal(newerComplete, newer!.Complete);
        Assert.Equal(!newerComplete, (await older).Complete);
        Assert.Equal(newerComplete ? 1 : 0, aggregator.LastCompletedEntries.Count);
        if (newerComplete) { Assert.Equal(2, aggregator.LastCompletedEntries[0].GetProperty("id").GetInt32()); }
    }

    [Fact]
    public async Task CanceledQueryRetainsItsOwnPartialSnapshotWithoutReplacingNewerQuery() {
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool drained = false;
        var aggregator = new CtLogAggregator {
            MinimumRequestSpacing = TimeSpan.Zero, MaxAttemptsPerRequest = 1,
            HttpHandlerFactory = () => new AsyncHandler(async (request, token) => {
                if (request.RequestUri!.Host == "slow.example" && request.RequestUri.AbsolutePath.Contains("old")) {
                    entered.TrySetResult(true);
                    try { await Task.Delay(System.Threading.Timeout.Infinite, token); }
                    finally { drained = true; }
                }
                return Json(request.RequestUri!.AbsolutePath.Contains("old") ? "[{\"id\":1}]" : "[{\"id\":2}]");
            })
        };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://fast.example/{0}");
        aggregator.ApiTemplates.Add("https://slow.example/{0}");
        using var guard = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var canceled = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        CtLogQueryResult? partial = null;
        var old = aggregator.QueryWithResultAsync("old", canceled.Token, result => partial = result);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            var newer = await aggregator.QueryWithResultAsync("new", guard.Token);
            canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => old);
            Assert.True(drained);
            Assert.False(partial!.Complete);
            Assert.Equal(1, Assert.Single(partial.Entries).GetProperty("id").GetInt32());
            Assert.Equal(2, partial.Sources.Count);
            Assert.True(newer.Complete);
            Assert.All(newer.Entries, entry => Assert.Equal(2, entry.GetProperty("id").GetInt32()));
            Assert.True(aggregator.LastQueryComplete);
        } finally {
            canceled.Cancel();
            try { await old; } catch (OperationCanceledException) { }
        }
    }
}
