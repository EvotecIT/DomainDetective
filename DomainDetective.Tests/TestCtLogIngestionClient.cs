using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO.Compression;
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
    public async Task ReadBatchAsync_ClampsLargeBatchSize_ToConfiguredMaximum() {
        Uri? requestedUri = null;
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                if (url.Contains("get-sth", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(CreateSuccessResponse("""{"tree_size":50000}"""));
                }

                if (url.Contains("get-entries", StringComparison.OrdinalIgnoreCase)) {
                    requestedUri = request.RequestUri;
                    return Task.FromResult(CreateSuccessResponse("""{"entries":[]}"""));
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://ct.example.test/",
                StartIndex = 10,
                BatchSize = 50_000,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.NotNull(requestedUri);
        string requestedUrl = requestedUri!.ToString();
        Assert.Contains("start=10", requestedUrl, StringComparison.Ordinal);
        Assert.Contains("end=8201", requestedUrl, StringComparison.Ordinal);
        Assert.Equal(10L, batch.StartIndex);
        Assert.Equal(9L, batch.EndIndex);
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
    public async Task GetLogsAsync_ReadsStaticCtTiledLogs() {
        var client = new CtLogIngestionClient {
            HttpGetOverride = static (_, _) => Task.FromResult("""
                {
                  "operators": [
                    {
                      "name": "Let's Encrypt",
                      "tiled_logs": [
                        {
                          "description": "Sycamore 2026h1",
                          "log_id": "abc123",
                          "key": "key123",
                          "mmd": 86400,
                          "submission_url": "https://log.sycamore.ct.example/2026h1/",
                          "monitoring_url": "https://mon.sycamore.ct.example/2026h1/",
                          "state": { "usable": { "timestamp": "2025-12-18T00:00:00Z" } },
                          "temporal_interval": {
                            "start_inclusive": "2025-12-18T00:00:00Z",
                            "end_exclusive": "2026-06-18T00:00:00Z"
                          }
                        }
                      ]
                    }
                  ]
                }
                """)
        };

        IReadOnlyList<CtLogDescriptor> logs = await client.GetLogsAsync("https://logs.example.test/list.json");

        CtLogDescriptor log = Assert.Single(logs);
        Assert.Equal(CtLogApiKind.StaticCt, log.ApiKind);
        Assert.Equal("https://log.sycamore.ct.example/2026h1/", log.Url);
        Assert.Equal("https://mon.sycamore.ct.example/2026h1/", log.MonitoringUrl);
        Assert.Equal("Let's Encrypt", log.OperatorName);
        Assert.Equal("usable", log.State);
        Assert.Equal("abc123", log.LogId);
        Assert.Equal("key123", log.PublicKey);
        Assert.Equal(86400, log.MaximumMergeDelaySeconds);
        Assert.True(log.IsUsable);
        Assert.False(log.IsReadOnly);
    }

    [Fact]
    public async Task GetLogsAsync_AcceptsStaticCtWithOnlyMonitoringUrl() {
        var client = new CtLogIngestionClient {
            HttpGetOverride = static (_, _) => Task.FromResult("""
                {
                  "operators": [
                    {
                      "name": "Static Only",
                      "tiled_logs": [
                        {
                          "description": "Monitor only",
                          "monitoring_url": "https://mon.static.example/log/",
                          "state": "usable"
                        }
                      ]
                    }
                  ]
                }
                """)
        };

        IReadOnlyList<CtLogDescriptor> logs = await client.GetLogsAsync("https://logs.example.test/list.json");

        CtLogDescriptor log = Assert.Single(logs);
        Assert.Equal(CtLogApiKind.StaticCt, log.ApiKind);
        Assert.Equal("https://mon.static.example/log/", log.Url);
        Assert.Equal("https://mon.static.example/log/", log.MonitoringUrl);
        Assert.Null(log.SubmissionUrl);
        Assert.True(log.IsUsable);
    }

    [Fact]
    public async Task GetLogsAsync_FiltersRejectedLogs_AndHonorsPendingOption() {
        var client = new CtLogIngestionClient {
            HttpGetOverride = static (_, _) => Task.FromResult("""
                {
                  "operators": [
                    {
                      "name": "Example",
                      "logs": [
                        {
                          "description": "Rejected",
                          "url": "https://rejected.ct.example/",
                          "state": "rejected"
                        },
                        {
                          "description": "Pending",
                          "url": "https://pending.ct.example/",
                          "state": { "pending": { "timestamp": "2026-01-01T00:00:00Z" } }
                        },
                        {
                          "description": "Readonly",
                          "url": "https://readonly.ct.example/",
                          "state": "readonly"
                        }
                      ]
                    }
                  ]
                }
                """)
        };

        IReadOnlyList<CtLogDescriptor> defaultLogs = await client.GetLogsAsync("https://logs.example.test/list.json");
        IReadOnlyList<CtLogDescriptor> withPending = await client.GetLogsAsync(
            "https://logs.example.test/list.json",
            includeRetired: false,
            includePending: true);

        CtLogDescriptor readonlyLog = Assert.Single(defaultLogs);
        Assert.Equal("https://readonly.ct.example/", readonlyLog.Url);
        Assert.True(readonlyLog.IsReadOnly);
        Assert.Equal([
            "https://pending.ct.example/",
            "https://readonly.ct.example/"
        ], withPending.Select(static log => log.Url).OrderBy(static value => value, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task GetLogsAsync_CanExcludeLogsWithoutLifecycleState() {
        var client = new CtLogIngestionClient {
            HttpGetOverride = static (_, _) => Task.FromResult("""
                {
                  "operators": [
                    {
                      "name": "Example",
                      "logs": [
                        {
                          "description": "No state",
                          "url": "https://unknown-state.ct.example/"
                        },
                        {
                          "description": "Usable",
                          "url": "https://usable.ct.example/",
                          "state": "usable"
                        }
                      ]
                    }
                  ]
                }
                """)
        };

        IReadOnlyList<CtLogDescriptor> defaultLogs = await client.GetLogsAsync("https://logs.example.test/list.json");
        IReadOnlyList<CtLogDescriptor> knownStateOnly = await client.GetLogsAsync(
            "https://logs.example.test/list.json",
            includeUnknownState: false);

        Assert.Equal([
            "https://unknown-state.ct.example/",
            "https://usable.ct.example/"
        ], defaultLogs.Select(static log => log.Url).OrderBy(static value => value, StringComparer.Ordinal).ToArray());
        CtLogDescriptor log = Assert.Single(knownStateOnly);
        Assert.Equal("https://usable.ct.example/", log.Url);
    }

    [Fact]
    public async Task GetTreeSizeAsync_ReadsStaticCtCheckpoint() {
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                Assert.Equal("https://mon.ct.example.test/2026h1/checkpoint", request.RequestUri?.ToString());
                return Task.FromResult(CreateTextResponse("""
                    log.ct.example.test/2026h1
                    12345
                    abc=

                    — log.ct.example.test/2026h1 sig=
                    """));
            }
        };

        long treeSize = await client.GetTreeSizeAsync(
            new CtLogDescriptor {
                Url = "https://log.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/"
            },
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.Equal(12345L, treeSize);
    }

    [Fact]
    public async Task GetTreeSizeAsync_RejectsStaticCtCheckpointWithNegativeTreeSize() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateTextResponse("""
                log.ct.example.test/2026h1
                -1
                abc=

                — log.ct.example.test/2026h1 sig=
                """))
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTreeSizeAsync(
                new CtLogDescriptor {
                    Url = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/"
                },
                TimeSpan.FromSeconds(5),
                CancellationToken.None));

        Assert.Contains("tree size", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTreeSizeAsync_RejectsStaticCtCheckpointWithoutTreeSizeLine() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateTextResponse("log.ct.example.test/2026h1"))
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTreeSizeAsync(
                new CtLogDescriptor {
                    Url = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/"
                },
                TimeSpan.FromSeconds(5),
                CancellationToken.None));

        Assert.Contains("tree size", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTreeSizeAsync_RejectsStaticCtCheckpointWithUnexpectedOrigin() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateTextResponse("""
                other.ct.example.test/2026h1
                12345
                abc=

                — other.ct.example.test/2026h1 sig=
                """))
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTreeSizeAsync(
                new CtLogDescriptor {
                    Url = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/"
                },
                TimeSpan.FromSeconds(5),
                CancellationToken.None));

        Assert.Contains("checkpoint origin", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("log.ct.example.test/2026h1", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTreeSizeAsync_RejectsStaticCtCheckpointWithoutExpectedOriginSignature() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateTextResponse("""
                log.ct.example.test/2026h1
                12345
                abc=

                — witness.ct.example.test sig=
                """))
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.GetTreeSizeAsync(
                new CtLogDescriptor {
                    Url = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/"
                },
                TimeSpan.FromSeconds(5),
                CancellationToken.None));

        Assert.Contains("note signature", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("log.ct.example.test/2026h1", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTreeSizeAsync_SkipsStaticCtCheckpointOriginValidation_WhenOnlyMonitoringUrlIsKnown() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => Task.FromResult(CreateTextResponse("""
                log.ct.example.test/2026h1
                12345
                abc=

                — log.ct.example.test/2026h1 sig=
                """))
        };

        long treeSize = await client.GetTreeSizeAsync(
            new CtLogDescriptor {
                Url = "https://mon.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/"
            },
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.Equal(12345L, treeSize);
    }

    [Fact]
    public async Task ReadBatchAsync_ReadsStaticCtDataTile() {
        byte[] certificateDer = LoadCertificateDer("multi.pem");
        byte[] tile = CreateStaticCtX509Tile(certificateDer, DateTimeOffset.Parse("2026-01-02T03:04:05Z"));
        Uri? requestedUri = null;
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                requestedUri = request.RequestUri;
                return Task.FromResult(CreateBinaryResponse(tile));
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://log.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                StartIndex = 0,
                BatchSize = 1,
                KnownTreeSize = 1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.Equal("https://mon.ct.example.test/2026h1/tile/data/000.p/1", requestedUri?.ToString());
        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(0L, entry.EntryIndex);
        Assert.Equal(CtLogEntryType.X509, entry.EntryType);
        Assert.Contains("site1.com", entry.Certificate.DnsNames, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadBatchAsync_ReadsGzipEncodedStaticCtDataTile() {
        byte[] certificateDer = LoadCertificateDer("multi.pem");
        byte[] tile = CreateStaticCtX509Tile(certificateDer, DateTimeOffset.Parse("2026-01-02T03:04:05Z"));
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                Assert.Contains("/tile/data/000.p/1", request.RequestUri?.ToString(), StringComparison.Ordinal);
                return Task.FromResult(CreateGzipResponse(tile));
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://log.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                StartIndex = 0,
                BatchSize = 1,
                KnownTreeSize = 1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(CtLogEntryType.X509, entry.EntryType);
        Assert.Contains("site1.com", entry.Certificate.DnsNames, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadBatchAsync_RejectsStaticCtDataTileWithOversizedContentLength() {
        var client = new CtLogIngestionClient {
            SendOverride = static (_, _) => {
                var content = new ByteArrayContent(Array.Empty<byte>());
                content.Headers.ContentLength = CtLogIngestionClient.MaxResponseBodyBytes + 1L;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = content
                });
            }
        };

        HttpRequestException exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.ReadBatchAsync(
                new CtLogIngestionBatchRequest {
                    LogUrl = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                    StartIndex = 0,
                    BatchSize = 1,
                    KnownTreeSize = 1,
                    RequestTimeout = TimeSpan.FromSeconds(5)
                },
                CancellationToken.None));

        Assert.Contains("limit", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadBatchAsync_FallsBackToFullStaticCtDataTile_WhenPartialTileIsGone() {
        byte[] certificateDer = LoadCertificateDer("multi.pem");
        byte[] fullTile = Enumerable
            .Range(0, 256)
            .SelectMany(index => CreateStaticCtX509Tile(
                certificateDer,
                DateTimeOffset.Parse("2026-01-02T03:04:05Z").AddSeconds(index)))
            .ToArray();
        List<string> requestedUrls = [];
        var client = new CtLogIngestionClient {
            SendOverride = (request, _) => {
                string url = request.RequestUri?.ToString() ?? string.Empty;
                requestedUrls.Add(url);
                if (url.EndsWith("/tile/data/000.p/1", StringComparison.Ordinal)) {
                    return Task.FromResult(CreateFailureResponse(HttpStatusCode.NotFound));
                }

                if (url.EndsWith("/tile/data/000", StringComparison.Ordinal)) {
                    return Task.FromResult(CreateBinaryResponse(fullTile));
                }

                throw new InvalidOperationException("Unexpected URL: " + url);
            }
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://log.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                StartIndex = 0,
                BatchSize = 1,
                KnownTreeSize = 1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        Assert.Equal([
            "https://mon.ct.example.test/2026h1/tile/data/000.p/1",
            "https://mon.ct.example.test/2026h1/tile/data/000"
        ], requestedUrls);
        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(0L, entry.EntryIndex);
        Assert.Equal(CtLogEntryType.X509, entry.EntryType);
        Assert.Contains("site1.com", entry.Certificate.DnsNames, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadBatchAsync_RejectsStaticCtDataTileWithUnexpectedEntryCount() {
        byte[] certificateDer = LoadCertificateDer("multi.pem");
        byte[] first = CreateStaticCtX509Tile(certificateDer, DateTimeOffset.Parse("2026-01-02T03:04:05Z"));
        byte[] second = CreateStaticCtX509Tile(certificateDer, DateTimeOffset.Parse("2026-01-02T03:04:06Z"));
        byte[] tile = first.Concat(second).ToArray();
        var client = new CtLogIngestionClient {
            SendOverride = (_, _) => Task.FromResult(CreateBinaryResponse(tile))
        };

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.ReadBatchAsync(
                new CtLogIngestionBatchRequest {
                    LogUrl = "https://log.ct.example.test/2026h1/",
                    ApiKind = CtLogApiKind.StaticCt,
                    MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                    StartIndex = 0,
                    BatchSize = 1,
                    KnownTreeSize = 1,
                    RequestTimeout = TimeSpan.FromSeconds(5)
                },
                CancellationToken.None));

        Assert.Contains("contained 2 entries", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadBatchAsync_ReadsStaticCtPrecertificateLeaf() {
        byte[] certificateDer = LoadCertificateDer("multi.pem");
        byte[] tile = CreateStaticCtPrecertificateTile(certificateDer, DateTimeOffset.Parse("2026-01-02T03:04:05Z"));
        var client = new CtLogIngestionClient {
            SendOverride = (_, _) => Task.FromResult(CreateBinaryResponse(tile))
        };

        CtLogIngestionBatch batch = await client.ReadBatchAsync(
            new CtLogIngestionBatchRequest {
                LogUrl = "https://log.ct.example.test/2026h1/",
                ApiKind = CtLogApiKind.StaticCt,
                MonitoringUrl = "https://mon.ct.example.test/2026h1/",
                StartIndex = 0,
                BatchSize = 1,
                KnownTreeSize = 1,
                RequestTimeout = TimeSpan.FromSeconds(5)
            },
            CancellationToken.None);

        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(CtLogEntryType.Precertificate, entry.EntryType);
        Assert.True(entry.IsPrecertificate);
        Assert.Contains("site1.com", entry.Certificate.DnsNames, StringComparer.OrdinalIgnoreCase);
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

    private static HttpResponseMessage CreateTextResponse(string text)
        => new(HttpStatusCode.OK) {
            Content = new StringContent(text, Encoding.UTF8, "text/plain")
        };

    private static HttpResponseMessage CreateBinaryResponse(byte[] bytes)
        => new(HttpStatusCode.OK) {
            Content = new ByteArrayContent(bytes)
        };

    private static HttpResponseMessage CreateGzipResponse(byte[] bytes) {
        using var compressedStream = new MemoryStream();
        using (var gzip = new GZipStream(compressedStream, CompressionMode.Compress, leaveOpen: true)) {
            gzip.Write(bytes, 0, bytes.Length);
        }

        var content = new ByteArrayContent(compressedStream.ToArray());
        content.Headers.ContentEncoding.Add("gzip");
        return new HttpResponseMessage(HttpStatusCode.OK) {
            Content = content
        };
    }

    private static byte[] LoadCertificateDer(string fileName) {
        string pem = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Data", fileName));
        string base64 = pem
            .Replace("-----BEGIN CERTIFICATE-----", string.Empty)
            .Replace("-----END CERTIFICATE-----", string.Empty)
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty)
            .Trim();
        return Convert.FromBase64String(base64);
    }

    private static byte[] CreateStaticCtX509Tile(byte[] certificateDer, DateTimeOffset timestampUtc) {
        using var stream = new MemoryStream();
        WriteUInt64(stream, (ulong)timestampUtc.ToUnixTimeMilliseconds());
        WriteUInt16(stream, 0);
        WriteVector24(stream, certificateDer);
        WriteVector16(stream, Array.Empty<byte>());
        WriteVector16(stream, Array.Empty<byte>());
        return stream.ToArray();
    }

    private static byte[] CreateStaticCtPrecertificateTile(byte[] certificateDer, DateTimeOffset timestampUtc) {
        using var stream = new MemoryStream();
        WriteUInt64(stream, (ulong)timestampUtc.ToUnixTimeMilliseconds());
        WriteUInt16(stream, 1);
        stream.Write(new byte[32], 0, 32);
        WriteVector24(stream, Array.Empty<byte>());
        WriteVector16(stream, Array.Empty<byte>());
        WriteVector24(stream, certificateDer);
        WriteVector16(stream, Array.Empty<byte>());
        return stream.ToArray();
    }

    private static void WriteUInt16(Stream stream, int value) {
        stream.WriteByte((byte)((value >> 8) & 0xff));
        stream.WriteByte((byte)(value & 0xff));
    }

    private static void WriteUInt64(Stream stream, ulong value) {
        for (int i = 7; i >= 0; i--) {
            stream.WriteByte((byte)((value >> (i * 8)) & 0xff));
        }
    }

    private static void WriteVector16(Stream stream, byte[] bytes) {
        WriteUInt16(stream, bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void WriteVector24(Stream stream, byte[] bytes) {
        stream.WriteByte((byte)((bytes.Length >> 16) & 0xff));
        stream.WriteByte((byte)((bytes.Length >> 8) & 0xff));
        stream.WriteByte((byte)(bytes.Length & 0xff));
        stream.Write(bytes, 0, bytes.Length);
    }
}
