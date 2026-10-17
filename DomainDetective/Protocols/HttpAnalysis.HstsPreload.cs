using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
using System.Threading;

namespace DomainDetective {
    public partial class HttpAnalysis {
        private sealed class HstsPreloadSnapshot {
            internal readonly HashSet<string> Exact;
            internal readonly HashSet<string> Subdomains;
            internal HstsPreloadSnapshot(HashSet<string> exact, HashSet<string> subdomains) {
                Exact = exact;
                Subdomains = subdomains;
            }
        }

        private static HstsPreloadSnapshot _hstsPreload = new(new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase));
        private static readonly object _hstsPreloadGate = new();
        private static string? _hstsPreloadSource;

        /// <summary>Reuses a parsed snapshot while the file identity, length and modification time are unchanged.</summary>
        internal static void EnsureHstsPreloadListLoaded(string filePath) {
            LoadHstsPreloadList(filePath, reuseUnchanged: true);
        }

        /// <summary>Loads a Chromium-derived HSTS preload snapshot, optionally gzip-compressed.</summary>
        /// <param name="filePath">File path containing the preload list.</param>
        public static void LoadHstsPreloadList(string filePath) {
            LoadHstsPreloadList(filePath, reuseUnchanged: false);
        }

        private static void LoadHstsPreloadList(string filePath, bool reuseUnchanged) {
            if (!File.Exists(filePath)) {
                return;
            }
            try {
                lock (_hstsPreloadGate) {
                    var info = new FileInfo(filePath);
                    string source = $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
                    if (reuseUnchanged && string.Equals(source, _hstsPreloadSource, StringComparison.Ordinal)) { return; }
                    using var file = File.OpenRead(filePath);
                    using var stream = filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
                        ? (Stream)new GZipStream(file, CompressionMode.Decompress)
                        : file;
                    using var document = JsonDocument.Parse(stream);
                    var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var subdomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var root = document.RootElement;
                    if (root.ValueKind == JsonValueKind.Array) {
                        foreach (var item in root.EnumerateArray()) {
                            if (item.ValueKind == JsonValueKind.String && NormalizeHstsHost(item.GetString()) is string host) exact.Add(host);
                        }
                    } else if (root.TryGetProperty("entries", out var entries)) {
                        foreach (var item in entries.EnumerateArray()) {
                            if (!item.TryGetProperty("name", out var nameProperty) || NormalizeHstsHost(nameProperty.GetString()) is not string host) continue;
                            exact.Add(host);
                            if (item.TryGetProperty("includeSubDomains", out var includeProperty) && includeProperty.ValueKind == JsonValueKind.True) {
                                subdomains.Add(host);
                            }
                        }
                    }
                    Volatile.Write(ref _hstsPreload, new HstsPreloadSnapshot(exact, subdomains));
                    _hstsPreloadSource = source;
                }
            } catch {
                // ignore malformed preload files
            }
        }

        internal static bool IsHstsPreloadedHost(string host) {
            var normalized = NormalizeHstsHost(host);
            if (normalized == null) return false;
            var snapshot = Volatile.Read(ref _hstsPreload);
            if (snapshot.Exact.Contains(normalized)) return true;
            var offset = normalized.IndexOf('.');
            while (offset >= 0 && offset + 1 < normalized.Length) {
                var parent = normalized.Substring(offset + 1);
                if (snapshot.Subdomains.Contains(parent)) return true;
                offset = normalized.IndexOf('.', offset + 1);
            }
            return false;
        }

        private static string? NormalizeHstsHost(string? host) {
            if (string.IsNullOrWhiteSpace(host)) return null;
            try {
                return new IdnMapping().GetAscii(host!.Trim().TrimEnd('.')).ToLowerInvariant();
            } catch (ArgumentException) {
                return null;
            }
        }

    }
}
