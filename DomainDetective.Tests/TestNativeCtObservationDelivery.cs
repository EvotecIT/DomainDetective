using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestNativeCtObservationDelivery {
    private const string LogUrl = "https://ct.test.example/delivery/";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CanceledObservationsRemainReplayable(bool shared) {
        using var scope = new CursorScope();
        string entry = MatchingEntry();
        using var caller = new CancellationTokenSource();
        bool cancel = true;
        var starts = new List<long>();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = async (url, token) => {
                if (url.Contains("get-sth")) return "{\"tree_size\":2}";
                long start = ReadStart(url); starts.Add(start);
                if (start == 0) return entry;
                if (cancel) { caller.Cancel(); await Task.Delay(Timeout.Infinite, token); }
                return "{\"entries\":[{}]}";
            }
        };
        var options = scope.Options();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => {
            if (shared) await source.DiscoverForDomainsAsync(new[] { "example.test" }, options, null, caller.Token);
            else await source.DiscoverAsync(options, null, caller.Token);
        });
        string key = shared ? NativeCtCursorState.BuildSharedKey(LogUrl, new[] { "example.test" })
            : NativeCtCursorState.BuildKey("example.test", LogUrl);
        var saved = NativeCtCursorState.Load(options.CursorStatePath);
        Assert.Null(saved.GetLastProcessedIndex(key));
        Assert.False(saved.IsCircuitOpen(NativeCtCursorState.BuildLogHealthKey(LogUrl), DateTimeOffset.UtcNow, out _));
        cancel = false;
        if (shared) {
            var result = await source.DiscoverForDomainsAsync(new[] { "example.test" }, options, null, default);
            Assert.Contains("found.example.test", result.SubdomainsByDomain["example.test"].Keys);
        } else {
            var result = await source.DiscoverAsync(options, null, default);
            Assert.Contains("found.example.test", result.Subdomains.Keys);
        }
        Assert.Equal(new long[] { 0, 1, 0, 1 }, starts);
    }

    [Fact]
    public async Task SharedCancellationDrainsWorkersAndPreservesPreviousCheckpoint() {
        using var scope = new CursorScope();
        using var caller = new CancellationTokenSource();
        string secondLog = "https://ct.test.example/second/";
        var options = scope.Options(); options.ExplicitLogUrls = new[] { LogUrl, secondLog }; options.MaxConcurrentLogs = 2;
        string[] keys = options.ExplicitLogUrls.Select(url => NativeCtCursorState.BuildSharedKey(url, new[] { "example.test" })).ToArray();
        var original = new NativeCtCursorState();
        foreach (string key in keys) original.SetLastProcessedIndex(key, 0);
        original.Save(options.CursorStatePath);
        string before = File.ReadAllText(options.CursorStatePath!);
        string entry = MatchingEntry();
        var bothWaiting = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int waiting = 0, cleaned = 0;
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = async (url, token) => {
                if (url.Contains("get-sth")) return "{\"tree_size\":3}";
                if (ReadStart(url) == 1) return entry;
                try {
                    if (Interlocked.Increment(ref waiting) == 2) bothWaiting.TrySetResult(true);
                    await bothWaiting.Task;
                    caller.Cancel();
                    await Task.Delay(Timeout.Infinite, token);
                    return "{\"entries\":[]}";
                } finally { Interlocked.Increment(ref cleaned); }
            }
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.DiscoverForDomainsAsync(
            new[] { "example.test" }, options, null, caller.Token));
        Assert.Equal(2, cleaned);
        Assert.Equal(before, File.ReadAllText(options.CursorStatePath!));
        var saved = NativeCtCursorState.Load(options.CursorStatePath);
        foreach (string key in keys) Assert.Equal(0, saved.GetLastProcessedIndex(key));
    }

    [Fact]
    public async Task SubdomainConsumerRetainsObservationsWhenLaterBatchFails() {
        using var scope = new CursorScope();
        string entry = MatchingEntry();
        var analysis = new SubdomainsAnalysis {
            EnableNativeCtLogSource = true, NativeCtLogOnly = true, VerifyStillResolves = false,
            NativeCtEntryBatchSize = 1, NativeCtInitialBackfillEntriesPerLog = 100,
            NativeCtCursorStatePath = scope.Options().CursorStatePath, NativeCtRetryCount = 0,
            QueryOverride = (url, _) => {
                if (url.Contains("get-sth")) return Task.FromResult("{\"tree_size\":2}");
                if (ReadStart(url) == 0) return Task.FromResult(entry);
                throw new TimeoutException("Later CT batch timed out.");
            }
        };
        analysis.NativeCtLogUrls.Add(LogUrl);
        await analysis.AnalyzeAsync("example.test");
        Assert.True(analysis.QuerySucceeded);
        Assert.Contains(analysis.Subdomains, item => item.Name == "found.example.test");
        Assert.Contains(analysis.NativeCtLogDiagnosticEntries, status => !string.IsNullOrEmpty(status.Failure));
        var saved = NativeCtCursorState.Load(scope.Options().CursorStatePath);
        Assert.Equal(0, saved.GetLastProcessedIndex(NativeCtCursorState.BuildKey("example.test", LogUrl)));
    }

    [Theory]
    [InlineData(404)]
    [InlineData(410)]
    public void CanonicalHttpFailuresRemainPermanentWithoutTypedRuntimeStatus(int status) {
        using var response = new HttpResponseMessage((HttpStatusCode)status);
        var canonical = CtLogIngestionClient.CreateRequestFailure(response);
        // net472 has only the message; persisted health ranking also has only this message.
        Assert.True(NativeCtLogSubdomainDiscovery.IsPermanentHttpLogFailure(new HttpRequestException(canonical.Message)));
        Assert.True(NativeCtLogSubdomainDiscovery.IsLikelyPermanentNativeCtFailure(canonical.Message));
        Assert.False(NativeCtLogSubdomainDiscovery.IsLikelyPermanentNativeCtFailure("HTTP 4040 Invalid status"));
    }

    [Fact]
    public async Task SubdomainConsumerPropagatesCancellationWithoutCommittingAbandonedMatches() {
        using var scope = new CursorScope();
        using var caller = new CancellationTokenSource();
        string entry = MatchingEntry();
        var analysis = new SubdomainsAnalysis {
            EnableNativeCtLogSource = true, NativeCtLogOnly = true, VerifyStillResolves = false,
            NativeCtEntryBatchSize = 1, NativeCtInitialBackfillEntriesPerLog = 100,
            NativeCtCursorStatePath = scope.Options().CursorStatePath, NativeCtRetryCount = 0,
            QueryOverride = (url, token) => {
                if (url.Contains("get-sth")) return Task.FromResult("{\"tree_size\":2}");
                if (ReadStart(url) == 0) return Task.FromResult(entry);
                caller.Cancel();
                token.ThrowIfCancellationRequested();
                return Task.FromResult("{\"entries\":[]}");
            }
        };
        analysis.NativeCtLogUrls.Add(LogUrl);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeAsync("example.test", null, caller.Token));
        Assert.Null(NativeCtCursorState.Load(scope.Options().CursorStatePath)
            .GetLastProcessedIndex(NativeCtCursorState.BuildKey("example.test", LogUrl)));
    }

    private static string MatchingEntry() {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=found.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = certificate.RawData;
        var leaf = new List<byte> { 0, 0 }; leaf.AddRange(new byte[10]);
        leaf.Add((byte)(der.Length >> 16)); leaf.Add((byte)(der.Length >> 8)); leaf.Add((byte)der.Length);
        leaf.AddRange(der); leaf.AddRange(new byte[2]);
        return "{\"entries\":[{\"leaf_input\":\"" + Convert.ToBase64String(leaf.ToArray()) + "\"}]}";
    }

    private static long ReadStart(string url) => long.Parse(new Uri(url).Query.TrimStart('?').Split('&')
        .Single(value => value.StartsWith("start=", StringComparison.Ordinal)).Substring(6), CultureInfo.InvariantCulture);

    private sealed class CursorScope : IDisposable {
        private readonly string _path = Path.Combine(Path.GetTempPath(), "dd-ct-delivery-" + Guid.NewGuid().ToString("N") + ".json");
        public NativeCtLogSubdomainDiscoveryOptions Options() => new() {
            BaseDomain = "example.test", ExplicitLogUrls = new[] { LogUrl }, CursorStatePath = _path,
            EntryBatchSize = 1, InitialBackfillEntriesPerLog = 100, MaxEntriesPerLog = 100,
            RetryCount = 0, CircuitBreakerFailureThreshold = 1
        };
        public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
    }
}
