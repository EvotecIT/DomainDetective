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
        var cursorPath = Path.Combine(Path.GetTempPath(), "dd-native-ct-circuit-" + Guid.NewGuid().ToString("N") + ".json");
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
                InitialBackfillEntriesPerLog = 100
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
            InitialBackfillEntriesPerLog = 100
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
        Assert.Equal("shared|https://ct.test.example/log1/", result.LogStatuses[0].CursorKey);
    }

    [Fact]
    public async Task DiscoverForDomainsAsync_UsesSharedCursorBetweenRuns() {
        var cursorPath = Path.Combine(Path.GetTempPath(), "dd-native-ct-cursor-" + Guid.NewGuid().ToString("N") + ".json");
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
                InitialBackfillEntriesPerLog = 100
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
    public async Task DiscoverForDomainsAsync_IncludesRetiredLogs_WhenEnabled() {
        using var cert = CreateSelfSigned("historical.example.com");
        var entriesJson = BuildCtEntriesResponse((cert, new DateTimeOffset(2022, 8, 11, 0, 0, 0, TimeSpan.Zero)));
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
