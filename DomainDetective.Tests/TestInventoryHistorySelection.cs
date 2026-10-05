using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public class TestInventoryHistorySelection {
    [Fact]
    public void LimitedQueriesUseActualTimestampsAndSkipInvalidPayloads() {
        using var scope = new HistoryScope();
        DateTimeOffset start = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        scope.Write("latest-looking-name.json", start, "old");
        scope.Write("legacy.json", start.AddDays(2), "latest");
        scope.Write("middle.json", start.AddDays(1), "middle");
        File.WriteAllText(Path.Combine(scope.Inventory, "corrupt.json"), "{bad");
        File.WriteAllText(Path.Combine(scope.Inventory, "invalid-entries.json"), "{\"CapturedAtUtc\":\"2026-10-10T00:00:00Z\",\"Entries\":\"invalid\"}");
        Assert.Equal("latest", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
        var limited = scope.Monitor.LoadInventorySnapshots(maxSnapshots: 2);
        Assert.Equal(new[] { "middle", "latest" }, new[] { limited[0].Entries[0].Host, limited[1].Entries[0].Host });
        Assert.Equal("middle", Assert.Single(scope.Monitor.LoadInventorySnapshots(untilUtc: start.AddDays(1), latestOnly: true)).Entries[0].Host);
        Assert.Empty(scope.Monitor.LoadInventorySnapshots(sinceUtc: start.AddDays(4), latestOnly: true));
    }

    [Fact]
    public void RepeatedSelectionObservesWritesDeletesAndReturnsIndependentPayloads() {
        using var scope = new HistoryScope();
        DateTimeOffset start = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        scope.Write("first.json", start, "first");
        var first = Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true));
        first.Entries[0].Host = "caller mutation";
        Assert.Equal("first", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
        scope.Write("second.json", start.AddDays(1), "second");
        Assert.Equal("second", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
        scope.Write("first.json", start.AddDays(2), "changed");
        File.SetLastWriteTimeUtc(Path.Combine(scope.Inventory, "first.json"), DateTime.UtcNow.AddMinutes(1));
        Assert.Equal("changed", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
        File.Delete(Path.Combine(scope.Inventory, "first.json"));
        Assert.Equal("second", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LimitedSelectionRetainsBomAndDuplicateTimestampSemantics(bool utf16) {
        using var scope = new HistoryScope();
        var encoding = utf16 ? Encoding.Unicode : new UTF8Encoding(true);
        File.WriteAllText(Path.Combine(scope.Inventory, "legacy.json"), "{\"CapturedAtUtc\":\"2026-10-01T00:00:00Z\",\"Entries\":[{\"Host\":\"legacy\"}],\"CapturedAtUtc\":\"2026-10-03T00:00:00Z\"}", encoding);
        scope.Write("new-looking-name.json", new DateTimeOffset(2026, 10, 2, 0, 0, 0, TimeSpan.Zero), "older");
        Assert.Equal("legacy", Assert.Single(scope.Monitor.LoadInventorySnapshots(latestOnly: true)).Entries[0].Host);
        Assert.Equal("legacy", scope.Monitor.LoadInventorySnapshots()[1].Entries[0].Host);
    }

    private sealed class HistoryScope : IDisposable {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "dd-history-" + Guid.NewGuid().ToString("N"));
        internal HistoryScope() {
            Inventory = Path.Combine(_root, "inventory");
            Directory.CreateDirectory(Inventory);
            Monitor = new CertificateMonitor { CacheDirectory = _root };
        }
        internal string Inventory { get; }
        internal CertificateMonitor Monitor { get; }
        internal void Write(string name, DateTimeOffset captured, string host) {
            var snapshot = new CertificateInventorySnapshot { CapturedAtUtc = captured, Entries = new List<CertificateInventoryEntry> { new() { Host = host } } };
            File.WriteAllText(Path.Combine(Inventory, name), JsonSerializer.Serialize(snapshot, JsonOptions.Default), Encoding.UTF8);
        }
        public void Dispose() { Monitor.Dispose(); Directory.Delete(_root, true); }
    }
}
