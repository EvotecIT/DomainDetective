using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DomainDetective.Helpers;

namespace DomainDetective;

public partial class CertificateMonitor {
    private readonly object _historyLock = new();
    private readonly Dictionary<string, InventoryFileMetadata> _historyMetadata = new(StringComparer.Ordinal);

    /// <summary>Loads persisted inventory snapshots from disk.</summary>
    /// <param name="sinceUtc">Optional lower bound for snapshot capture time.</param>
    /// <param name="untilUtc">Optional upper bound for snapshot capture time.</param>
    /// <param name="maxSnapshots">Optional maximum number of snapshots to return (latest N).</param>
    /// <param name="latestOnly">When true, returns only the latest available snapshot after filtering.</param>
    /// <remarks>Limited queries materialize only selected payloads. Capture-time metadata is reused within this monitor while a file's size and last-write time remain unchanged.</remarks>
    public IReadOnlyList<CertificateInventorySnapshot> LoadInventorySnapshots(
        DateTimeOffset? sinceUtc = null,
        DateTimeOffset? untilUtc = null,
        int maxSnapshots = 0,
        bool latestOnly = false) {
        if (sinceUtc.HasValue && untilUtc.HasValue && sinceUtc.Value > untilUtc.Value) {
            return Array.Empty<CertificateInventorySnapshot>();
        }
        lock (_historyLock) {
            if (!Directory.Exists(InventoryDirectory)) {
                _historyMetadata.Clear();
                return Array.Empty<CertificateInventorySnapshot>();
            }
            string[] files = Directory.GetFiles(InventoryDirectory, "*.json", SearchOption.TopDirectoryOnly);
            var present = new HashSet<string>(files, StringComparer.Ordinal);
            foreach (string removed in _historyMetadata.Keys.Where(path => !present.Contains(path)).ToArray()) {
                _historyMetadata.Remove(removed);
            }
            if (!latestOnly && maxSnapshots <= 0) {
                var all = new List<CertificateInventorySnapshot>();
                foreach (string path in files) {
                    try {
                        var snapshot = ReadInventoryFile<CertificateInventorySnapshot>(path);
                        if (snapshot != null && MatchesHistoryRange(snapshot.CapturedAtUtc, sinceUtc, untilUtc)) {
                            all.Add(snapshot);
                        }
                    } catch {
                        // Preserve the unlimited query's single payload read per file.
                    }
                }
                return all.OrderBy(snapshot => snapshot.CapturedAtUtc).ToArray();
            }
            var candidates = new List<(string Path, DateTimeOffset CapturedAtUtc, int Order)>();
            for (int index = 0; index < files.Length; index++) {
                string path = files[index];
                try {
                    var info = new FileInfo(path);
                    if (!_historyMetadata.TryGetValue(path, out var metadata) || metadata.Length != info.Length || metadata.LastWriteUtc != info.LastWriteTimeUtc) {
                        var header = ReadInventoryFile<InventorySnapshotHeader>(path);
                        if (header == null) {
                            _historyMetadata.Remove(path);
                            continue;
                        }
                        metadata = new InventoryFileMetadata(info.Length, info.LastWriteTimeUtc, header.CapturedAtUtc);
                        _historyMetadata[path] = metadata;
                    }
                    if (!metadata.InvalidPayload && MatchesHistoryRange(metadata.CapturedAtUtc, sinceUtc, untilUtc)) {
                        candidates.Add((path, metadata.CapturedAtUtc, index));
                    }
                } catch {
                    _historyMetadata.Remove(path);
                    // Unreadable or invalid files do not prevent another usable snapshot.
                }
            }
            int limit = latestOnly ? 1 : maxSnapshots > 0 ? maxSnapshots : int.MaxValue;
            var snapshots = new List<(CertificateInventorySnapshot Snapshot, int Order)>();
            foreach (var candidate in candidates.OrderByDescending(item => item.CapturedAtUtc).ThenByDescending(item => item.Order)) {
                try {
                    var snapshot = ReadInventoryFile<CertificateInventorySnapshot>(candidate.Path);
                    if (snapshot == null || !MatchesHistoryRange(snapshot.CapturedAtUtc, sinceUtc, untilUtc)) {
                        continue;
                    }
                    snapshots.Add((snapshot, candidate.Order));
                    if (snapshots.Count == limit) {
                        break;
                    }
                } catch {
                    if (_historyMetadata.TryGetValue(candidate.Path, out var metadata)) {
                        metadata.InvalidPayload = true;
                    }
                }
            }
            return snapshots.OrderBy(item => item.Snapshot.CapturedAtUtc).ThenBy(item => item.Order)
                .Select(item => item.Snapshot).ToArray();
        }
    }

    private static T? ReadInventoryFile<T>(string path) where T : class {
        using var stream = File.OpenRead(path);
        int first = stream.ReadByte();
        int second = stream.ReadByte();
        int third = stream.ReadByte();
        if (first == 0xef && second == 0xbb && third == 0xbf) {
            stream.Position = 3;
        } else if ((first == 0xff && second == 0xfe) || (first == 0xfe && second == 0xff) || (first == 0 && second == 0 && third == 0xfe)) {
            stream.Position = 0;
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            return JsonSerializer.Deserialize<T>(reader.ReadToEnd(), JsonOptions.Default);
        } else {
            stream.Position = 0;
        }
        return JsonSerializer.Deserialize<T>(stream, JsonOptions.Default);
    }

    private static bool MatchesHistoryRange(DateTimeOffset capturedAtUtc, DateTimeOffset? sinceUtc, DateTimeOffset? untilUtc) =>
        (!sinceUtc.HasValue || capturedAtUtc >= sinceUtc.Value) && (!untilUtc.HasValue || capturedAtUtc <= untilUtc.Value);

    // A built-in serializer metadata projection skips entry construction. It also retains
    // JSON timestamp semantics (including legacy filenames and duplicate properties).
    private sealed class InventorySnapshotHeader {
        public DateTimeOffset CapturedAtUtc { get; set; }
    }

    private sealed class InventoryFileMetadata {
        internal InventoryFileMetadata(long length, DateTime lastWriteUtc, DateTimeOffset capturedAtUtc) {
            Length = length;
            LastWriteUtc = lastWriteUtc;
            CapturedAtUtc = capturedAtUtc;
        }
        internal long Length { get; }
        internal DateTime LastWriteUtc { get; }
        internal DateTimeOffset CapturedAtUtc { get; }
        internal bool InvalidPayload { get; set; }
    }
}
