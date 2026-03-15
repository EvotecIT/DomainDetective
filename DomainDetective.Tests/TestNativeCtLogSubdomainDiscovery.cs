using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestNativeCtLogSubdomainDiscovery {
    [Fact]
    public void BuildSharedKey_IncludesReadableScopePreview() {
        string key = NativeCtCursorState.BuildSharedKey(
            "https://ct.test.example/log1/",
            new[] { "example.com", "evotec.xyz", "eurofins.com", "evotec.pl" });

        Assert.Contains("eurofins.com", key, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("plus1", key, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://ct.test.example/log1/", key, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_RetriesTransientRequestsBeforeSuccess() {
        using var cert = CreateSelfSigned("portal.example.com");
        var entriesJson = BuildCtEntriesResponse((cert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)));
        var getSthCalls = 0;

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    getSthCalls++;
                    if (getSthCalls < 3) {
                        throw new HttpRequestException("Simulated transient CT failure.");
                    }
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            RetryCount = 2,
            RetryBaseDelay = TimeSpan.Zero,
            RetryMaxDelay = TimeSpan.Zero
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(3, getSthCalls);
        Assert.Equal(1, result.CertificateObservationCount);
        Assert.Contains("portal.example.com", result.SubdomainsByDomain["example.com"].Keys);
        Assert.Single(result.LogStatuses);
        Assert.True(result.LogStatuses[0].Succeeded);
        Assert.False(result.LogStatuses[0].SkippedByCircuitBreaker);
        Assert.Equal("https://ct.test.example/log1/", result.LogStatuses[0].LogUrl);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_CircuitBreakerSkipsLogAfterFailureThreshold() {
        string cursorPath = CreateTemporaryCursorStatePath();
        var getSthCalls = 0;

        try {
            var source = new NativeCtLogSubdomainDiscovery {
                QueryOverride = (url, _) => {
                    if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                    }
                    if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                        getSthCalls++;
                        throw new HttpRequestException("Simulated CT outage.");
                    }

                    throw new InvalidOperationException("Unexpected URL: " + url);
                }
            };

            var options = new NativeCtLogSubdomainDiscoveryOptions {
                BaseDomain = "example.com",
                LogListUrl = "https://ct-log-list.example/logs.json",
                CursorStatePath = cursorPath,
                RetryCount = 0,
                CircuitBreakerFailureThreshold = 1,
                CircuitBreakerDuration = TimeSpan.FromMinutes(5),
                MaxCtRowsToProcess = 100,
                MaxSubdomains = 100,
                MaxLogsToProcess = 10,
                MaxEntriesPerLog = 100,
                EntryBatchSize = 100,
                InitialBackfillEntriesPerLog = 100,
                IncludeRetiredLogs = false
            };

            var first = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);
            var second = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);

            Assert.False(first.SourceSucceeded);
            Assert.False(second.SourceSucceeded);
            Assert.Equal(1, getSthCalls);
            Assert.Contains(second.Warnings, warning => warning.Contains("circuit open", StringComparison.OrdinalIgnoreCase));
            Assert.Single(first.LogStatuses);
            Assert.Single(second.LogStatuses);
            Assert.False(first.LogStatuses[0].Succeeded);
            Assert.NotNull(first.LogStatuses[0].Failure);
            Assert.True(second.LogStatuses[0].SkippedByCircuitBreaker);
            Assert.NotNull(second.LogStatuses[0].CircuitOpenUntilUtc);
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_GlobalLogCircuitBreakerSkipsDeadLogAcrossDifferentScopes() {
        string cursorPath = CreateTemporaryCursorStatePath();
        var getSthCalls = 0;

        try {
            var source = new NativeCtLogSubdomainDiscovery {
                QueryOverride = (url, _) => {
                    if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                    }
                    if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                        getSthCalls++;
                        throw new HttpRequestException("Simulated shared CT outage.");
                    }

                    throw new InvalidOperationException("Unexpected URL: " + url);
                }
            };

            var options = new NativeCtLogSubdomainDiscoveryOptions {
                BaseDomain = "example.com",
                LogListUrl = "https://ct-log-list.example/logs.json",
                CursorStatePath = cursorPath,
                RetryCount = 0,
                CircuitBreakerFailureThreshold = 1,
                CircuitBreakerDuration = TimeSpan.FromMinutes(5),
                MaxCtRowsToProcess = 100,
                MaxSubdomains = 100,
                MaxLogsToProcess = 10,
                MaxEntriesPerLog = 100,
                EntryBatchSize = 100,
                InitialBackfillEntriesPerLog = 100,
                IncludeRetiredLogs = false
            };

            var first = await source.DiscoverForDomainsAsync(
                new[] { "example.com", "evotec.xyz" },
                options,
                new InternalLogger(),
                CancellationToken.None);
            var second = await source.DiscoverForDomainsAsync(
                new[] { "eurofins.com", "evotec.pl" },
                options,
                new InternalLogger(),
                CancellationToken.None);

            Assert.False(first.SourceSucceeded);
            Assert.False(second.SourceSucceeded);
            Assert.Equal(1, getSthCalls);
            Assert.Single(first.LogStatuses);
            Assert.Single(second.LogStatuses);
            Assert.False(first.LogStatuses[0].Succeeded);
            Assert.True(second.LogStatuses[0].SkippedByCircuitBreaker);
            Assert.NotNull(second.LogStatuses[0].CircuitOpenUntilUtc);
            Assert.Equal(
                NativeCtCursorState.BuildSharedKey(
                    "https://ct.test.example/log1/",
                    new[] { "eurofins.com", "evotec.pl" }),
                second.LogStatuses[0].CursorKey);
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_NameResolutionFailureTripsGlobalCircuitImmediately() {
        string cursorPath = CreateTemporaryCursorStatePath();
        var getSthCalls = 0;

        try {
            var source = new NativeCtLogSubdomainDiscovery {
                QueryOverride = (url, _) => {
                    if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase) ||
                        url.Contains("all_logs_list.json", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/retired/"" } ] } ] }");
                    }
                    if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                        getSthCalls++;
                        throw new HttpRequestException("No such host is known. (ct.test.example:443)");
                    }

                    throw new InvalidOperationException("Unexpected URL: " + url);
                }
            };

            var options = new NativeCtLogSubdomainDiscoveryOptions {
                BaseDomain = "example.com",
                LogListUrl = "https://ct-log-list.example/logs.json",
                CursorStatePath = cursorPath,
                RetryCount = 0,
                CircuitBreakerFailureThreshold = 3,
                CircuitBreakerDuration = TimeSpan.FromMinutes(5),
                MaxCtRowsToProcess = 100,
                MaxSubdomains = 100,
                MaxLogsToProcess = 10,
                MaxEntriesPerLog = 100,
                EntryBatchSize = 100,
                InitialBackfillEntriesPerLog = 100,
                IncludeRetiredLogs = true
            };

            var first = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);
            var second = await source.DiscoverForDomainsAsync(
                new[] { "eurofins.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);

            Assert.False(first.SourceSucceeded);
            Assert.False(second.SourceSucceeded);
            Assert.Equal(1, getSthCalls);
            Assert.Single(first.LogStatuses);
            Assert.Single(second.LogStatuses);
            Assert.False(first.LogStatuses[0].Succeeded);
            Assert.True(second.LogStatuses[0].SkippedByCircuitBreaker);
            Assert.NotNull(second.LogStatuses[0].CircuitOpenUntilUtc);
            Assert.Contains(second.Warnings, warning => warning.Contains("circuit open", StringComparison.OrdinalIgnoreCase));
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_CorrelatesEntriesAcrossDomains() {
        using var exampleCert = CreateSelfSigned("portal.example.com");
        using var evotecCert = CreateSelfSigned("api.evotec.xyz");
        var entriesJson = BuildCtEntriesResponse(
            (exampleCert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)),
            (evotecCert, new DateTimeOffset(2026, 1, 11, 0, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 2 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com", "evotec.xyz" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(2, result.CertificateObservationCount);
        Assert.True(result.SubdomainsByDomain.TryGetValue("example.com", out var exampleMap));
        Assert.True(result.SubdomainsByDomain.TryGetValue("evotec.xyz", out var evotecMap));
        Assert.Contains("portal.example.com", exampleMap!.Keys);
        Assert.Contains("api.evotec.xyz", evotecMap!.Keys);
        Assert.Single(result.LogStatuses);
        Assert.True(result.LogStatuses[0].Succeeded);
        Assert.Equal(
            NativeCtCursorState.BuildSharedKey(
                "https://ct.test.example/log1/",
                new[] { "example.com", "evotec.xyz" }),
            result.LogStatuses[0].CursorKey);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_UsesSharedCursorBetweenRuns() {
        string cursorPath = CreateTemporaryCursorStatePath();
        try {
            using var cert = CreateSelfSigned("portal.example.com");
            var entriesJson = BuildCtEntriesResponse((cert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)));
            var getEntriesCalls = 0;
            var source = new NativeCtLogSubdomainDiscovery {
                QueryOverride = (url, _) => {
                    if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                    }
                    if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""tree_size"": 1 }");
                    }
                    if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                        getEntriesCalls++;
                        return Task.FromResult(entriesJson);
                    }

                    throw new InvalidOperationException("Unexpected URL: " + url);
                }
            };

            var options = new NativeCtLogSubdomainDiscoveryOptions {
                BaseDomain = "example.com",
                LogListUrl = "https://ct-log-list.example/logs.json",
                CursorStatePath = cursorPath,
                MaxCtRowsToProcess = 100,
                MaxSubdomains = 100,
                MaxLogsToProcess = 10,
                MaxEntriesPerLog = 100,
                EntryBatchSize = 100,
                InitialBackfillEntriesPerLog = 100,
                IncludeRetiredLogs = false
            };

            var first = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);
            var second = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);

            Assert.True(first.SourceSucceeded);
            Assert.True(second.SourceSucceeded);
            Assert.Equal(1, first.CertificateObservationCount);
            Assert.Equal(0, second.CertificateObservationCount);
            Assert.Equal(1, getEntriesCalls);
            Assert.Single(first.LogStatuses);
            Assert.Single(second.LogStatuses);
            Assert.True(first.LogStatuses[0].Succeeded);
            Assert.True(second.LogStatuses[0].Succeeded);
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_IsolatesSharedCursorByDomainSet() {
        string cursorPath = CreateTemporaryCursorStatePath();
        try {
            using var exampleCert = CreateSelfSigned("portal.example.com");
            using var evotecCert = CreateSelfSigned("api.evotec.xyz");
            var exampleEntriesJson = BuildCtEntriesResponse((exampleCert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)));
            var evotecEntriesJson = BuildCtEntriesResponse((evotecCert, new DateTimeOffset(2026, 1, 11, 0, 0, 0, TimeSpan.Zero)));
            var getEntriesCalls = 0;

            var source = new NativeCtLogSubdomainDiscovery {
                QueryOverride = (url, _) => {
                    if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"" } ] } ] }");
                    }
                    if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                        return Task.FromResult(@"{ ""tree_size"": 1 }");
                    }
                    if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                        getEntriesCalls++;
                        return Task.FromResult(
                            getEntriesCalls == 1
                                ? exampleEntriesJson
                                : evotecEntriesJson);
                    }

                    throw new InvalidOperationException("Unexpected URL: " + url);
                }
            };

            var options = new NativeCtLogSubdomainDiscoveryOptions {
                BaseDomain = "example.com",
                LogListUrl = "https://ct-log-list.example/logs.json",
                CursorStatePath = cursorPath,
                MaxCtRowsToProcess = 100,
                MaxSubdomains = 100,
                MaxLogsToProcess = 10,
                MaxEntriesPerLog = 100,
                EntryBatchSize = 100,
                InitialBackfillEntriesPerLog = 100,
                IncludeRetiredLogs = false
            };

            var first = await source.DiscoverForDomainsAsync(
                new[] { "example.com" },
                options,
                new InternalLogger(),
                CancellationToken.None);
            var second = await source.DiscoverForDomainsAsync(
                new[] { "evotec.xyz" },
                options,
                new InternalLogger(),
                CancellationToken.None);

            Assert.True(first.SourceSucceeded);
            Assert.True(second.SourceSucceeded);
            Assert.Equal(2, getEntriesCalls);
            Assert.Contains("portal.example.com", first.SubdomainsByDomain["example.com"].Keys);
            Assert.Contains("api.evotec.xyz", second.SubdomainsByDomain["evotec.xyz"].Keys);
            Assert.NotEqual(first.LogStatuses[0].CursorKey, second.LogStatuses[0].CursorKey);
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public void ApplyLogCap_SpreadsSelectionAcrossTemporalIntervals_WhenCapped() {
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs =
            new (string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)[] {
                ("https://ct.example/log-2022/", new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2022, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2023/", new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2023, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2024/", new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2024, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2025/", new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2025, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2026/", new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero))
            };

        IReadOnlyList<string> selected = NativeCtLogSubdomainDiscovery.ApplyLogCap(logs, 3);

        Assert.Equal(3, selected.Count);
        Assert.Contains("https://ct.example/log-2022/", selected);
        Assert.Contains("https://ct.example/log-2024/", selected);
        Assert.Contains("https://ct.example/log-2026/", selected);
    }

    [Fact]
    public void ApplyLogCap_InterleavesOldAndNewLogs_WhenUncapped() {
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs =
            new (string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)[] {
                ("https://ct.example/log-2022/", new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2022, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2023/", new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2023, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2024/", new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2024, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2025/", new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2025, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2026/", new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero))
            };

        IReadOnlyList<string> ordered = NativeCtLogSubdomainDiscovery.ApplyLogCap(logs, 0);

        Assert.Equal(5, ordered.Count);
        Assert.Equal("https://ct.example/log-2022/", ordered[0]);
        Assert.Equal("https://ct.example/log-2026/", ordered[1]);
        Assert.Equal("https://ct.example/log-2023/", ordered[2]);
        Assert.Equal("https://ct.example/log-2025/", ordered[3]);
        Assert.Equal("https://ct.example/log-2024/", ordered[4]);
    }

    [Fact]
    public void ApplyLogCap_PrioritizeLatestExactMatch_OrdersNewestLogsFirst() {
        IReadOnlyList<(string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)> logs =
            new (string Url, DateTimeOffset? TemporalStartUtc, DateTimeOffset? TemporalEndUtc)[] {
                ("https://ct.example/log-2022/", new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2022, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2023/", new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2023, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2024/", new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2024, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2025/", new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2025, 12, 31, 0, 0, 0, TimeSpan.Zero)),
                ("https://ct.example/log-2026/", new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 12, 31, 0, 0, 0, TimeSpan.Zero))
            };

        IReadOnlyList<string> ordered = NativeCtLogSubdomainDiscovery.ApplyLogCap(logs, 0, prioritizeLatestExactMatch: true);

        Assert.Equal(5, ordered.Count);
        Assert.Equal("https://ct.example/log-2026/", ordered[0]);
        Assert.Equal("https://ct.example/log-2025/", ordered[1]);
        Assert.Equal("https://ct.example/log-2024/", ordered[2]);
        Assert.Equal("https://ct.example/log-2023/", ordered[3]);
        Assert.Equal("https://ct.example/log-2022/", ordered[4]);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_IncludesRetiredLogs_WhenEnabled() {
        using var cert = CreateSelfSigned("historical.example.com");
        var entriesJson = BuildCtEntriesResponse((cert, new DateTimeOffset(2022, 8, 11, 0, 0, 0, TimeSpan.Zero)));
        var requestedUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                requestedUrls.Add(url);
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(url, "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/usable/"", ""state"": { ""usable"": {} } }, { ""url"": ""ct.test.example/retired/"", ""state"": { ""retired"": {} } } ] } ] }");
                }
                if (url.Contains("ct.test.example/usable/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 0 }");
                }
                if (url.Contains("ct.test.example/retired/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("ct.test.example/retired/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }
                if (url.Contains("ct.test.example/usable/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""entries"": [] }");
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = true
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Contains("historical.example.com", result.SubdomainsByDomain["example.com"].Keys);
        Assert.Contains(requestedUrls, static url => url.Contains("ct.test.example/retired/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_SkipsKnownBogusRetiredLogEntries() {
        var requestedSthUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(url, "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(
                        @"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [
                            { ""description"": ""Bogus RFC6962 log to avoid breaking misbehaving CT libraries"", ""url"": ""https://ct.example.com/bogus/ipng/"", ""state"": { ""retired"": {} } },
                            { ""description"": ""Retired historical log"", ""url"": ""ct.test.example/retired/"", ""state"": { ""retired"": {} } }
                        ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    requestedSthUrls.Add(url);
                    return Task.FromResult(@"{ ""tree_size"": 0 }");
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = true
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Single(requestedSthUrls);
        Assert.Contains(requestedSthUrls, static url => url.Contains("ct.test.example/retired/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(requestedSthUrls, static url => url.Contains("ct.example.com/bogus", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.LogStatuses, static status => status.LogUrl.Contains("ct.example.com/bogus", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_CappedRunPrefersCurrentLogsBeforeRetiredLogs() {
        var requestedSthUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(url, "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(
                        @"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [
                            { ""url"": ""ct.test.example/current-a/"", ""state"": { ""usable"": {} } },
                            { ""url"": ""ct.test.example/current-b/"", ""state"": { ""usable"": {} } },
                            { ""url"": ""ct.test.example/current-c/"", ""state"": { ""usable"": {} } },
                            { ""url"": ""ct.test.example/current-d/"", ""state"": { ""usable"": {} } },
                            { ""url"": ""ct.test.example/retired-2022/"", ""state"": { ""retired"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2022-01-01T00:00:00Z"", ""end_exclusive"": ""2023-01-01T00:00:00Z"" } },
                            { ""url"": ""ct.test.example/retired-2023/"", ""state"": { ""retired"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2023-01-01T00:00:00Z"", ""end_exclusive"": ""2024-01-01T00:00:00Z"" } },
                            { ""url"": ""ct.test.example/retired-2024/"", ""state"": { ""retired"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2024-01-01T00:00:00Z"", ""end_exclusive"": ""2025-01-01T00:00:00Z"" } },
                            { ""url"": ""ct.test.example/retired-2025/"", ""state"": { ""retired"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2025-01-01T00:00:00Z"", ""end_exclusive"": ""2026-01-01T00:00:00Z"" } }
                        ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    requestedSthUrls.Add(url);
                    return Task.FromResult(@"{ ""tree_size"": 0 }");
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 3,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = true
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(3, requestedSthUrls.Count);
        Assert.Equal(2, requestedSthUrls.Count(static url => url.Contains("ct.test.example/current-", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(1, requestedSthUrls.Count(static url => url.Contains("ct.test.example/retired-", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(requestedSthUrls, static url => url.Contains("ct.test.example/retired-2025/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(requestedSthUrls, static url => url.Contains("ct.test.example/retired-2022/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NativeCtCursorState_LoadAndSave_SkipKnownBogusLogEntries() {
        string cursorPath = CreateTemporaryCursorStatePath();

        try {
            File.WriteAllText(
                cursorPath,
                """
                {
                  "Version": 2,
                  "UpdatedAtUtc": "2026-03-14T16:53:40Z",
                  "Entries": [
                    {
                      "Key": "health|https://ct.example.com/bogus/ipng/",
                      "LastProcessedIndex": null,
                      "ConsecutiveFailureCount": 1
                    },
                    {
                      "Key": "health|https://ct.test.example/retired/",
                      "LastProcessedIndex": 123,
                      "ConsecutiveFailureCount": 0
                    }
                  ]
                }
                """);

            NativeCtCursorState state = NativeCtCursorState.Load(cursorPath);

            Assert.Null(state.GetLastProcessedIndex("health|https://ct.example.com/bogus/ipng/"));
            Assert.Equal(123, state.GetLastProcessedIndex("health|https://ct.test.example/retired/"));

            state.Save(cursorPath);
            string saved = File.ReadAllText(cursorPath);

            Assert.DoesNotContain("ct.example.com/bogus", saved, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("ct.test.example/retired", saved, StringComparison.OrdinalIgnoreCase);
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_SkipsRetiredLogs_WhenDisabled() {
        var requestedUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                requestedUrls.Add(url);
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/usable/"", ""state"": { ""usable"": {} } }, { ""url"": ""ct.test.example/retired/"", ""state"": { ""retired"": {} } } ] } ] }");
                }
                if (url.Contains("ct.test.example/usable/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 0 }");
                }
                if (url.Contains("ct.test.example/usable/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""entries"": [] }");
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Empty(result.SubdomainsByDomain["example.com"]);
        Assert.DoesNotContain(requestedUrls, static url => url.Contains("ct.test.example/retired/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_UsesHistoricalOfficialLogList_WhenRetiredLogsEnabled() {
        using var cert = CreateSelfSigned("historical.example.com");
        var entriesJson = BuildCtEntriesResponse((cert, new DateTimeOffset(2022, 8, 11, 0, 0, 0, TimeSpan.Zero)));
        var requestedUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                requestedUrls.Add(url);
                if (string.Equals(url, "https://ct-log-list.example/logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Current"", ""logs"": [ { ""url"": ""ct.test.example/current/"", ""state"": { ""usable"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2026-01-01T00:00:00Z"", ""end_exclusive"": ""2027-01-01T00:00:00Z"" } } ] } ] }");
                }
                if (string.Equals(url, "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Historical"", ""logs"": [ { ""url"": ""ct.test.example/historical/"", ""state"": { ""retired"": {} } } ] } ] }");
                }
                if (url.Contains("ct.test.example/current/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 0 }");
                }
                if (url.Contains("ct.test.example/current/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""entries"": [] }");
                }
                if (url.Contains("ct.test.example/historical/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("ct.test.example/historical/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = true
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Contains("historical.example.com", result.SubdomainsByDomain["example.com"].Keys);
        Assert.Contains(
            requestedUrls,
            static url => string.Equals(url, "https://www.gstatic.com/ct/log_list/v2/all_logs_list.json", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_MaxCtRowsCountsMatchedObservationsOnly() {
        using var unrelatedCert = CreateSelfSigned("unrelated.example.net");
        using var matchingCert = CreateSelfSigned("historical.example.com");
        var entriesJson = BuildCtEntriesResponse(
            (unrelatedCert, new DateTimeOffset(2026, 1, 10, 0, 0, 0, TimeSpan.Zero)),
            (matchingCert, new DateTimeOffset(2026, 1, 11, 0, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"", ""state"": { ""usable"": {} } } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 2 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "example.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 1,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "example.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(1, result.CertificateObservationCount);
        Assert.Contains("historical.example.com", result.SubdomainsByDomain["example.com"].Keys);
        Assert.DoesNotContain("unrelated.example.net", result.SubdomainsByDomain["example.com"].Keys);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_ExactHostSeedsMatchRequestedHost() {
        using var exactHostCert = CreateSelfSigned("airtoxics.eurofins.com");
        var entriesJson = BuildCtEntriesResponse((exactHostCert, new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"", ""state"": { ""usable"": {} } } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "airtoxics.eurofins.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            ExactMatchDomains = new[] { "airtoxics.eurofins.com" }
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "airtoxics.eurofins.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(1, result.CertificateObservationCount);
        Assert.Contains("airtoxics.eurofins.com", result.SubdomainsByDomain["airtoxics.eurofins.com"].Keys);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_ExactHostSeedsDoNotPullDeeperChildren() {
        using var deeperChildCert = CreateSelfSigned("foo.airtoxics.eurofins.com");
        var entriesJson = BuildCtEntriesResponse((deeperChildCert, new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"", ""state"": { ""usable"": {} } } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "airtoxics.eurofins.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            ExactMatchDomains = new[] { "airtoxics.eurofins.com" }
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "airtoxics.eurofins.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(0, result.CertificateObservationCount);
        Assert.Empty(result.SubdomainsByDomain["airtoxics.eurofins.com"]);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_ExactHostSeedsMatchSingleLabelWildcardCoverage() {
        using var wildcardCert = CreateSelfSigned("*.eurofins.com");
        var entriesJson = BuildCtEntriesResponse((wildcardCert, new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"", ""state"": { ""usable"": {} } } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "airtoxics.eurofins.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            ExactMatchDomains = new[] { "airtoxics.eurofins.com" }
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "airtoxics.eurofins.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(1, result.CertificateObservationCount);
        Assert.Contains("airtoxics.eurofins.com", result.SubdomainsByDomain["airtoxics.eurofins.com"].Keys);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_ExactHostSeedsDoNotMatchMultiLabelWildcardCoverage() {
        using var wildcardCert = CreateSelfSigned("*.eurofins.com");
        var entriesJson = BuildCtEntriesResponse((wildcardCert, new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero)));

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log1/"", ""state"": { ""usable"": {} } } ] } ] }");
                }
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(entriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "foo.airtoxics.eurofins.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            ExactMatchDomains = new[] { "foo.airtoxics.eurofins.com" }
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "foo.airtoxics.eurofins.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(0, result.CertificateObservationCount);
        Assert.Empty(result.SubdomainsByDomain["foo.airtoxics.eurofins.com"]);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_ExactHostFastPathPrefersNewestLogAndStopsEarly() {
        using var newerCert = CreateSelfSigned("airtoxics.eurofins.com");
        using var olderCert = CreateSelfSigned("airtoxics.eurofins.com");
        var newerEntriesJson = BuildCtEntriesResponse((newerCert, new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero)));
        var olderEntriesJson = BuildCtEntriesResponse((olderCert, new DateTimeOffset(2022, 7, 11, 15, 36, 47, TimeSpan.Zero)));
        var requestedUrls = new List<string>();

        var source = new NativeCtLogSubdomainDiscovery {
            QueryOverride = (url, _) => {
                requestedUrls.Add(url);
                if (url.Contains("logs.json", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""operators"": [ { ""name"": ""Test"", ""logs"": [ { ""url"": ""ct.test.example/log-2022/"", ""state"": { ""usable"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2022-01-01T00:00:00Z"", ""end_exclusive"": ""2023-01-01T00:00:00Z"" } }, { ""url"": ""ct.test.example/log-2026/"", ""state"": { ""usable"": {} }, ""temporal_interval"": { ""start_inclusive"": ""2026-01-01T00:00:00Z"", ""end_exclusive"": ""2027-01-01T00:00:00Z"" } } ] } ] }");
                }
                if (url.Contains("ct.test.example/log-2026/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("ct.test.example/log-2026/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(newerEntriesJson);
                }
                if (url.Contains("ct.test.example/log-2022/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(@"{ ""tree_size"": 1 }");
                }
                if (url.Contains("ct.test.example/log-2022/", StringComparison.OrdinalIgnoreCase) && url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(olderEntriesJson);
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        var options = new NativeCtLogSubdomainDiscoveryOptions {
            BaseDomain = "airtoxics.eurofins.com",
            LogListUrl = "https://ct-log-list.example/logs.json",
            MaxCtRowsToProcess = 100,
            MaxSubdomains = 100,
            MaxLogsToProcess = 10,
            MaxEntriesPerLog = 100,
            EntryBatchSize = 100,
            InitialBackfillEntriesPerLog = 100,
            IncludeRetiredLogs = false,
            ExactMatchDomains = new[] { "airtoxics.eurofins.com" },
            PrioritizeLatestExactMatch = true,
            StopAfterMatchedObservations = 1
        };

        var result = await source.DiscoverForDomainsAsync(
            new[] { "airtoxics.eurofins.com" },
            options,
            new InternalLogger(),
            CancellationToken.None);

        Assert.True(result.SourceSucceeded);
        Assert.Equal(1, result.CertificateObservationCount);
        Assert.Contains("airtoxics.eurofins.com", result.SubdomainsByDomain["airtoxics.eurofins.com"].Keys);
        Assert.Equal(
            new DateTimeOffset(2026, 3, 6, 10, 0, 0, TimeSpan.Zero),
            result.SubdomainsByDomain["airtoxics.eurofins.com"]["airtoxics.eurofins.com"].LatestCertificateCtEntryTimestampUtc);
        Assert.Contains(
            requestedUrls,
            static url => url.Contains("ct.test.example/log-2026/", StringComparison.OrdinalIgnoreCase) &&
                          url.Contains("get-entries", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            requestedUrls,
            static url => url.Contains("ct.test.example/log-2022/", StringComparison.OrdinalIgnoreCase) &&
                          url.Contains("get-entries", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Warnings, warning => warning.Contains("matched-observation target", StringComparison.OrdinalIgnoreCase));
    }

    private static X509Certificate2 CreateSelfSigned(string cn) {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return new X509Certificate2(cert.Export(X509ContentType.Cert));
    }

    private static string BuildCtEntriesResponse(params (X509Certificate2 Cert, DateTimeOffset TimestampUtc)[] items) {
        var entries = items.Select(item => {
            var leafInput = BuildCtLeafInput(item.Cert, item.TimestampUtc.ToUnixTimeMilliseconds());
            return @"{ ""leaf_input"": """ + leafInput + @""", ""extra_data"": """" }";
        });
        return @"{ ""entries"": [ " + string.Join(",", entries) + " ] }";
    }

    private static string BuildCtLeafInput(X509Certificate2 certificate, long timestampMs) {
        var certBytes = certificate.Export(X509ContentType.Cert);
        var buffer = new List<byte>(certBytes.Length + 32) {
            0x00,
            0x00
        };

        AddUInt64(buffer, (ulong)timestampMs);
        AddUInt16(buffer, 0);
        AddUInt24(buffer, certBytes.Length);
        buffer.AddRange(certBytes);
        AddUInt16(buffer, 0);

        return Convert.ToBase64String(buffer.ToArray());
    }

    private static string CreateTemporaryCursorStatePath() {
        string path = Path.GetTempFileName();
        File.Delete(path);
        return path;
    }

    private static void AddUInt16(ICollection<byte> buffer, int value) {
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void AddUInt24(ICollection<byte> buffer, int value) {
        buffer.Add((byte)((value >> 16) & 0xFF));
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void AddUInt64(ICollection<byte> buffer, ulong value) {
        for (var i = 7; i >= 0; i--) {
            buffer.Add((byte)((value >> (8 * i)) & 0xFF));
        }
    }
}
