using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DomainDetective;
using DomainDetective.CLI.Commands;
using DomainDetective.Helpers;

namespace DomainDetective.CLI.Tests;

[Collection("HttpListener")]
public class TestCertificateInventoryExports {
    [Fact]
    public void WriteUtf8Text_WritesPlainAndGzip() {
        var tempDirectory = CreateTempDirectory();
        try {
            var plainPath = Path.Combine(tempDirectory, "plain", "export.txt");
            var gzipPath = Path.Combine(tempDirectory, "gzip", "export.txt.gz");
            const string content = "row-1\nrow-2\n";

            CertificateInventoryCommandHelpers.WriteUtf8Text(plainPath, content);
            CertificateInventoryCommandHelpers.WriteUtf8Text(gzipPath, content);

            Assert.True(File.Exists(plainPath));
            Assert.True(File.Exists(gzipPath));
            Assert.Equal(content, File.ReadAllText(plainPath, Encoding.UTF8));
            Assert.Equal(content, ReadGzipText(gzipPath));
        } finally {
            DeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task SummaryCommand_WritesCsvAndNdjsonGzip() {
        var tempDirectory = CreateTempDirectory();
        try {
            var cacheDirectory = Path.Combine(tempDirectory, "cache");
            var inventoryDirectory = Path.Combine(cacheDirectory, "inventory");
            Directory.CreateDirectory(inventoryDirectory);

            var now = DateTimeOffset.UtcNow;
            var snapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = now.AddMinutes(-10),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "expiring.example.com",
                        ResolvedHost = "expiring.example.com",
                        Port = 443,
                        Scheme = "https",
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Demo Issuer",
                        CertificateRootIssuerNormalized = "Demo Root",
                        NotAfterUtc = now.AddDays(5),
                        Valid = true,
                        ChainComplete = true,
                        IsReachable = true,
                        AllowsServerAuthentication = true,
                        CtDiscoverySources = new[] { "crt.sh" }
                    }
                }
            };

            WriteSnapshot(inventoryDirectory, "snapshot-summary.json", snapshot);

            var csvPath = Path.Combine(tempDirectory, "out", "summary.csv");
            var ndjsonPath = Path.Combine(tempDirectory, "out", "summary.ndjson.gz");
            var command = new CertificateInventorySummaryCommand();
            var settings = new CertificateInventorySummarySettings {
                CacheDirectory = cacheDirectory,
                CsvPath = csvPath,
                NdjsonPath = ndjsonPath,
                ExpiringWithinDays = 30,
                MaxExpiring = 20,
                Json = true
            };

            var result = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, result);
            Assert.True(File.Exists(csvPath));
            Assert.True(File.Exists(ndjsonPath));

            var csv = File.ReadAllText(csvPath, Encoding.UTF8);
            Assert.Contains("RowType,Category,Name,Count", csv);
            Assert.Contains("Summary", csv);
            Assert.Contains("ExpiringEndpoint", csv);

            var ndjson = ReadGzipText(ndjsonPath);
            Assert.Contains("\"RowType\":\"Summary\"", ndjson);
            Assert.Contains("\"RowType\":\"Counter\"", ndjson);
            Assert.Contains("\"RowType\":\"ExpiringEndpoint\"", ndjson);
        } finally {
            DeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DiffCommand_WritesCsvGzipAndNdjson() {
        var tempDirectory = CreateTempDirectory();
        try {
            var cacheDirectory = Path.Combine(tempDirectory, "cache");
            var inventoryDirectory = Path.Combine(cacheDirectory, "inventory");
            Directory.CreateDirectory(inventoryDirectory);

            var olderSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddHours(-2),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "changed.example.com",
                        ResolvedHost = "changed.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Issuer A",
                        CertificateRootIssuerNormalized = "Root A",
                        CertificateThumbprint = "AA:AA",
                        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(20),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    }
                }
            };

            var newerSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = DateTimeOffset.UtcNow.AddHours(-1),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "changed.example.com",
                        ResolvedHost = "changed.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Issuer B",
                        CertificateRootIssuerNormalized = "Root B",
                        CertificateThumbprint = "BB:BB",
                        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(40),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    }
                }
            };

            WriteSnapshot(inventoryDirectory, "snapshot-old.json", olderSnapshot);
            WriteSnapshot(inventoryDirectory, "snapshot-new.json", newerSnapshot);

            var csvPath = Path.Combine(tempDirectory, "out", "diff.csv.gz");
            var ndjsonPath = Path.Combine(tempDirectory, "out", "diff.ndjson");
            var command = new CertificateInventoryDiffCommand();
            var settings = new CertificateInventoryDiffSettings {
                CacheDirectory = cacheDirectory,
                CsvPath = csvPath,
                NdjsonPath = ndjsonPath,
                Json = true,
                MaxEndpoints = 100
            };

            var result = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, result);
            Assert.True(File.Exists(csvPath));
            Assert.True(File.Exists(ndjsonPath));

            var csv = ReadGzipText(csvPath);
            Assert.Contains("Host,Port,ProbeVantage,Status,ChangeReasons", csv);
            Assert.Contains("Changed", csv);
            Assert.Contains("changed.example.com", csv);

            var ndjson = File.ReadAllText(ndjsonPath, Encoding.UTF8);
            Assert.Contains("\"Status\":\"Changed\"", ndjson);
            Assert.Contains("\"Host\":\"changed.example.com\"", ndjson);
        } finally {
            DeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task SnapshotsCommand_WritesCsvAndNdjson_WithUntilFilter() {
        var tempDirectory = CreateTempDirectory();
        try {
            var cacheDirectory = Path.Combine(tempDirectory, "cache");
            var inventoryDirectory = Path.Combine(cacheDirectory, "inventory");
            Directory.CreateDirectory(inventoryDirectory);

            var oldestSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 1, 10, 12, 0, 0, TimeSpan.Zero),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "old.example.com",
                        ResolvedHost = "old.example.com",
                        Port = 443,
                        Valid = true,
                        AllowsServerAuthentication = true
                    }
                }
            };

            var latestSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 1, 20, 12, 0, 0, TimeSpan.Zero),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "latest.example.com",
                        ResolvedHost = "latest.example.com",
                        Port = 443,
                        Valid = true,
                        AllowsServerAuthentication = true
                    }
                }
            };

            WriteSnapshot(inventoryDirectory, "snapshot-oldest.json", oldestSnapshot);
            WriteSnapshot(inventoryDirectory, "snapshot-latest.json", latestSnapshot);

            var csvPath = Path.Combine(tempDirectory, "out", "snapshots.csv");
            var ndjsonPath = Path.Combine(tempDirectory, "out", "snapshots.ndjson.gz");
            var command = new CertificateInventorySnapshotsCommand();
            var settings = new CertificateInventorySnapshotsSettings {
                CacheDirectory = cacheDirectory,
                UntilUtc = new DateTime(2026, 1, 15, 0, 0, 0, DateTimeKind.Utc),
                CsvPath = csvPath,
                NdjsonPath = ndjsonPath,
                Json = true
            };

            var result = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, result);
            Assert.True(File.Exists(csvPath));
            Assert.True(File.Exists(ndjsonPath));

            var csv = File.ReadAllText(csvPath, Encoding.UTF8);
            Assert.Contains("CapturedAtUtc,Port,EntryCount,UniqueEndpointCount", csv);
            Assert.Contains("2026-01-10T12:00:00.0000000Z", csv);
            Assert.DoesNotContain("2026-01-20T12:00:00.0000000Z", csv);

            var ndjson = ReadGzipText(ndjsonPath);
            var lines = ndjson.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            Assert.Single(lines);

            using var doc = JsonDocument.Parse(lines[0]);
            var root = doc.RootElement;
            Assert.Equal("Snapshot", root.GetProperty("RowType").GetString());
            Assert.Equal(1, root.GetProperty("ReturnedSnapshotCount").GetInt32());
            Assert.Equal(1, root.GetProperty("ExcludedByUntilCount").GetInt32());
        } finally {
            DeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DiffCommand_UsesSnapshotIndexesForSelection() {
        var tempDirectory = CreateTempDirectory();
        try {
            var cacheDirectory = Path.Combine(tempDirectory, "cache");
            var inventoryDirectory = Path.Combine(cacheDirectory, "inventory");
            Directory.CreateDirectory(inventoryDirectory);

            var oldestSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 1, 10, 12, 0, 0, TimeSpan.Zero),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "index.example.com",
                        ResolvedHost = "index.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Issuer A",
                        CertificateRootIssuerNormalized = "Root A",
                        CertificateThumbprint = "AA:AA",
                        NotAfterUtc = new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    }
                }
            };

            var middleSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "index.example.com",
                        ResolvedHost = "index.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Issuer B",
                        CertificateRootIssuerNormalized = "Root B",
                        CertificateThumbprint = "BB:BB",
                        NotAfterUtc = new DateTimeOffset(2026, 4, 1, 12, 0, 0, TimeSpan.Zero),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    }
                }
            };

            var latestSnapshot = new CertificateInventorySnapshot {
                CapturedAtUtc = new DateTimeOffset(2026, 1, 20, 12, 0, 0, TimeSpan.Zero),
                Port = 443,
                Entries = new List<CertificateInventoryEntry> {
                    new CertificateInventoryEntry {
                        Host = "index.example.com",
                        ResolvedHost = "index.example.com",
                        Port = 443,
                        Service = "HTTPS",
                        CertificateIssuerNormalized = "Issuer C",
                        CertificateRootIssuerNormalized = "Root C",
                        CertificateThumbprint = "CC:CC",
                        NotAfterUtc = new DateTimeOffset(2026, 5, 1, 12, 0, 0, TimeSpan.Zero),
                        Valid = true,
                        ChainComplete = true,
                        HostnameMatch = true
                    }
                }
            };

            WriteSnapshot(inventoryDirectory, "snapshot-oldest.json", oldestSnapshot);
            WriteSnapshot(inventoryDirectory, "snapshot-middle.json", middleSnapshot);
            WriteSnapshot(inventoryDirectory, "snapshot-latest.json", latestSnapshot);

            var csvPath = Path.Combine(tempDirectory, "out", "diff-index.csv");
            var command = new CertificateInventoryDiffCommand();
            var settings = new CertificateInventoryDiffSettings {
                CacheDirectory = cacheDirectory,
                PreviousIndex = 2,
                CurrentIndex = 1,
                CsvPath = csvPath,
                Json = true,
                MaxEndpoints = 100
            };

            var result = await command.ExecuteForTestingAsync(null!, settings);

            Assert.Equal(0, result);
            Assert.True(File.Exists(csvPath));

            var csv = File.ReadAllText(csvPath, Encoding.UTF8);
            Assert.Contains("index.example.com", csv);
            Assert.Contains("2026-01-10T12:00:00.0000000Z", csv);
            Assert.Contains("2026-01-15T12:00:00.0000000Z", csv);
            Assert.DoesNotContain("2026-01-20T12:00:00.0000000Z", csv);
        } finally {
            DeleteDirectory(tempDirectory);
        }
    }

    private static void WriteSnapshot(string directory, string fileName, CertificateInventorySnapshot snapshot) {
        var path = Path.Combine(directory, fileName);
        var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
        File.WriteAllText(path, json, Encoding.UTF8);
    }

    private static string ReadGzipText(string path) {
        using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzipStream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static string CreateTempDirectory() {
        var path = Path.Combine(Path.GetTempPath(), "DomainDetective", "cli-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectory(string path) {
        if (Directory.Exists(path)) {
            Directory.Delete(path, recursive: true);
        }
    }
}
