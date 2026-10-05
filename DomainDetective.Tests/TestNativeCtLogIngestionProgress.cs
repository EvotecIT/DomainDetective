using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestNativeCtLogIngestionProgress {
    private const string LogUrl = "https://ct.test.example/progress/";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShortBatchesContinueAtFirstUnreturnedIndex(bool shared) {
        using var scope = new CursorScope();
        var starts = new List<long>();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("get-sth")) return Task.FromResult("{\"tree_size\":6}");
                starts.Add(ReadStart(url));
                return Task.FromResult(Entries(2));
            }
        };
        var options = scope.Options();
        options.EntryBatchSize = 4;
        var statuses = await Run(source, options, shared);
        Assert.Equal(new long[] { 0, 2, 4 }, starts);
        Assert.Equal(5, Assert.Single(statuses).LastProcessedIndex);
        starts.Clear();
        await Run(source, options, shared);
        Assert.Empty(starts); // A restart does not replay or skip an unprocessed prefix.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MalformedPositionsKeepTheirOriginalLogIndexes(bool shared) {
        using var scope = new CursorScope();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => Task.FromResult(url.Contains("get-sth")
                ? "{\"tree_size\":4}" : "{\"entries\":[null,{}, {\"leaf_input\":\"invalid\"},true]}")
        };
        var statuses = await Run(source, scope.Options(), shared);
        Assert.Equal(3, Assert.Single(statuses).LastProcessedIndex);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EmptyBatchDoesNotAdvanceCursor(bool shared) {
        using var scope = new CursorScope();
        var starts = new List<long>();
        bool empty = true;
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("get-sth")) return Task.FromResult("{\"tree_size\":2}");
                starts.Add(ReadStart(url));
                return Task.FromResult(Entries(empty ? 0 : 2));
            }
        };
        Assert.Null(Assert.Single(await Run(source, scope.Options(), shared)).LastProcessedIndex);
        empty = false;
        Assert.Equal(1, Assert.Single(await Run(source, scope.Options(), shared)).LastProcessedIndex);
        Assert.Equal(new long[] { 0, 0 }, starts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerCancellationLeavesCheckpointUnchangedWithoutOpeningCircuit(bool shared) {
        using var scope = new CursorScope();
        using var caller = new CancellationTokenSource();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = async (url, token) => {
                if (url.Contains("get-sth")) return "{\"tree_size\":4}";
                if (ReadStart(url) == 0) return Entries(2);
                caller.Cancel();
                await Task.Delay(Timeout.Infinite, token);
                return Entries(2);
            }
        };
        var options = scope.Options(); options.EntryBatchSize = 2;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Run(source, options, shared, caller.Token));
        var saved = NativeCtCursorState.Load(options.CursorStatePath);
        string key = shared ? NativeCtCursorState.BuildSharedKey(LogUrl, new[] { "example.test" })
            : NativeCtCursorState.BuildKey("example.test", LogUrl);
        Assert.Null(saved.GetLastProcessedIndex(key));
        Assert.False(saved.IsCircuitOpen(NativeCtCursorState.BuildLogHealthKey(LogUrl), DateTimeOffset.UtcNow, out _));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PartiallyProcessedCertificateRemainsEligibleOnRestart(bool shared) {
        using var scope = new CursorScope();
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=first.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("first.example.test"); names.AddDnsName("second.example.test");
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] der = certificate.RawData;
        var leaf = new List<byte> { 0, 0 }; leaf.AddRange(new byte[8]); leaf.AddRange(new byte[2]);
        leaf.Add((byte)(der.Length >> 16)); leaf.Add((byte)(der.Length >> 8)); leaf.Add((byte)der.Length);
        leaf.AddRange(der); leaf.AddRange(new byte[2]);
        string entries = "{\"entries\":[{\"leaf_input\":\"" + Convert.ToBase64String(leaf.ToArray()) + "\"}]}";
        var starts = new List<long>();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("get-sth")) return Task.FromResult("{\"tree_size\":1}");
                starts.Add(ReadStart(url)); return Task.FromResult(entries);
            }
        };
        var options = scope.Options(); options.MaxSubdomains = 1;
        Assert.Null(Assert.Single(await Run(source, options, shared)).LastProcessedIndex);
        options.MaxSubdomains = 10;
        if (shared) {
            var result = await source.DiscoverForDomainsAsync(new[] { "example.test" }, options, new InternalLogger(), default);
            Assert.Contains("second.example.test", result.SubdomainsByDomain["example.test"].Keys);
            Assert.Equal(0, Assert.Single(result.LogStatuses).LastProcessedIndex);
        } else {
            var result = await source.DiscoverAsync(options, new InternalLogger(), default);
            Assert.Contains("second.example.test", result.Subdomains.Keys);
            Assert.Equal(0, Assert.Single(result.LogStatuses).LastProcessedIndex);
        }
        Assert.Equal(new long[] { 0, 0 }, starts);
    }

    [Theory]
    [InlineData(false, "{}")] [InlineData(true, "{}")]
    [InlineData(false, "{\"entries\":[{},{}]}")] [InlineData(true, "{\"entries\":[{},{}]}")]
    public async Task InvalidBatchEnvelopeDoesNotClaimSuccessfulIngestion(bool shared, string response) {
        using var scope = new CursorScope();
        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => Task.FromResult(url.Contains("get-sth") ? "{\"tree_size\":1}" : response)
        };
        var status = Assert.Single(await Run(source, scope.Options(), shared));
        Assert.False(status.Succeeded); Assert.NotNull(status.Failure); Assert.Null(status.LastProcessedIndex);
    }

    private static async Task<IReadOnlyList<NativeCtLogIngestionStatus>> Run(NativeCtLogSubdomainDiscovery source,
        NativeCtLogSubdomainDiscoveryOptions options, bool shared, CancellationToken token = default) {
        if (shared) return (await source.DiscoverForDomainsAsync(new[] { "example.test" }, options, new InternalLogger(), token)).LogStatuses;
        return (await source.DiscoverAsync(options, new InternalLogger(), token)).LogStatuses;
    }

    private static long ReadStart(string url) => long.Parse(new Uri(url).Query.TrimStart('?').Split('&')
        .Single(value => value.StartsWith("start=", StringComparison.Ordinal)).Substring(6), System.Globalization.CultureInfo.InvariantCulture);
    private static string Entries(int count) => "{\"entries\":[" + string.Join(",", Enumerable.Repeat("{\"leaf_input\":\"invalid\"}", count)) + "]}";

    private sealed class CursorScope : IDisposable {
        private readonly string _path = Path.Combine(Path.GetTempPath(), "dd-ct-progress-" + Guid.NewGuid().ToString("N") + ".json");
        public NativeCtLogSubdomainDiscoveryOptions Options() => new() {
            BaseDomain = "example.test", ExplicitLogUrls = new[] { LogUrl }, CursorStatePath = _path,
            EntryBatchSize = 8, InitialBackfillEntriesPerLog = 100, MaxEntriesPerLog = 100,
            RetryCount = 0, CircuitBreakerFailureThreshold = 1
        };
        public void Dispose() { if (File.Exists(_path)) File.Delete(_path); }
    }
}
