using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestNativeCtLogSubdomainDiscovery {
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
        } finally {
            try {
                if (File.Exists(cursorPath)) {
                    File.Delete(cursorPath);
                }
            } catch {
            }
        }
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
