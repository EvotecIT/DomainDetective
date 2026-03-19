using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;


internal sealed class NativeCtCursorState {
    private const string KnownBogusCtLogUrlPrefix = "https://ct.example.com/bogus/";
    private readonly Dictionary<string, NativeCtCursorEntryState> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();

    public long? GetLastProcessedIndex(string key) {
        if (string.IsNullOrWhiteSpace(key)) {
            return null;
        }
        lock (_sync) {
            return _entries.TryGetValue(key, out var entry) ? entry.LastProcessedIndex : null;
        }
    }

    public void SetLastProcessedIndex(string key, long value) {
        if (string.IsNullOrWhiteSpace(key)) {
            return;
        }
        if (value < 0) {
            return;
        }
        lock (_sync) {
            var entry = GetOrCreateEntry(key);
            entry.LastProcessedIndex = value;
        }
    }

    public bool IsCircuitOpen(string key, DateTimeOffset nowUtc, out DateTimeOffset openUntilUtc) {
        openUntilUtc = default;
        if (string.IsNullOrWhiteSpace(key)) {
            return false;
        }
        lock (_sync) {
            if (!_entries.TryGetValue(key, out var entry)) {
                return false;
            }
            if (!entry.CircuitOpenUntilUtc.HasValue) {
                return false;
            }
            if (entry.CircuitOpenUntilUtc.Value <= nowUtc) {
                return false;
            }

            openUntilUtc = entry.CircuitOpenUntilUtc.Value;
            return true;
        }
    }

    public void RecordFailure(
        string key,
        DateTimeOffset nowUtc,
        string? errorMessage,
        int threshold,
        TimeSpan duration) {
        if (string.IsNullOrWhiteSpace(key)) {
            return;
        }

        var normalizedThreshold = threshold < 1 ? 1 : threshold;
        var normalizedDuration = duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : duration;

        lock (_sync) {
            var entry = GetOrCreateEntry(key);
            entry.LastAttemptUtc = nowUtc;
            entry.LastError = NormalizeError(errorMessage);
            entry.ConsecutiveFailureCount++;
            if (entry.ConsecutiveFailureCount >= normalizedThreshold) {
                var level = entry.ConsecutiveFailureCount - normalizedThreshold;
                var factor = Math.Pow(2, Math.Min(3, level));
                var openFor = TimeSpan.FromMilliseconds(normalizedDuration.TotalMilliseconds * factor);
                entry.CircuitOpenUntilUtc = nowUtc.Add(openFor);
            }
        }
    }

    public void RecordSuccess(string key, DateTimeOffset nowUtc) {
        if (string.IsNullOrWhiteSpace(key)) {
            return;
        }

        lock (_sync) {
            var entry = GetOrCreateEntry(key);
            entry.LastAttemptUtc = nowUtc;
            entry.LastSuccessUtc = nowUtc;
            entry.ConsecutiveFailureCount = 0;
            entry.CircuitOpenUntilUtc = null;
            entry.LastError = null;
        }
    }

    public static string BuildKey(string baseDomain, string logUrl) {
        return $"{baseDomain}|{logUrl}";
    }

    public static string BuildSharedKey(string logUrl, IReadOnlyCollection<string>? domains) {
        if (domains == null || domains.Count == 0) {
            return $"shared|{logUrl}";
        }

        string scope = BuildSharedScopeFingerprint(domains);
        return $"shared|{scope}|{logUrl}";
    }

    public static string BuildLogHealthKey(string logUrl) {
        return $"health|{logUrl}";
    }

    public bool TryGetLogHealthSnapshot(string logUrl, out NativeCtCursorEntrySnapshot snapshot) {
        return TryGetEntrySnapshot(BuildLogHealthKey(logUrl), out snapshot);
    }

    public bool TryGetEntrySnapshot(string key, out NativeCtCursorEntrySnapshot snapshot) {
        snapshot = default;
        if (string.IsNullOrWhiteSpace(key)) {
            return false;
        }

        lock (_sync) {
            if (!_entries.TryGetValue(key, out var entry)) {
                return false;
            }

            snapshot = new NativeCtCursorEntrySnapshot(
                entry.LastProcessedIndex,
                entry.ConsecutiveFailureCount,
                entry.CircuitOpenUntilUtc,
                entry.LastAttemptUtc,
                entry.LastSuccessUtc,
                entry.LastError);
            return true;
        }
    }

    private static string BuildSharedScopeFingerprint(IReadOnlyCollection<string> domains) {
        IReadOnlyList<string> normalizedDomains = domains
            .Where(static domain => !string.IsNullOrWhiteSpace(domain))
            .Select(static domain => domain.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static domain => domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
        string normalizedScope = string.Join(",", normalizedDomains);
        if (string.IsNullOrWhiteSpace(normalizedScope)) {
            return "global";
        }

        byte[] bytes = Encoding.UTF8.GetBytes(normalizedScope);
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(bytes);
        string hashText = BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
        string preview = BuildSharedScopePreview(normalizedDomains);
        return preview + "--" + hashText.Substring(0, 12);
    }

    private static string BuildSharedScopePreview(IReadOnlyList<string> normalizedDomains) {
        if (normalizedDomains == null || normalizedDomains.Count == 0) {
            return "global";
        }

        var previewDomains = normalizedDomains.Take(3).ToList();
        string preview = string.Join("+", previewDomains);
        if (normalizedDomains.Count > previewDomains.Count) {
            preview += "+plus" + (normalizedDomains.Count - previewDomains.Count).ToString(CultureInfo.InvariantCulture);
        }

        return preview;
    }

    public static NativeCtCursorState Load(string? path) {
        var state = new NativeCtCursorState();
        if (string.IsNullOrWhiteSpace(path)) {
            return state;
        }
        if (!File.Exists(path)) {
            return state;
        }

        try {
            var json = File.ReadAllText(path);
            var payload = JsonSerializer.Deserialize<NativeCtCursorStateDocument>(json, new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true
            });
            if (payload == null || payload.Entries == null || payload.Entries.Count == 0) {
                return state;
            }

            foreach (var item in payload.Entries) {
                var key = item.Key;
                if (string.IsNullOrWhiteSpace(key)) {
                    continue;
                }
                if (ContainsIgnoredLogUrl(key)) {
                    continue;
                }

                var entry = state.GetOrCreateEntry(key);
                if (item.LastProcessedIndex.HasValue && item.LastProcessedIndex.Value >= 0) {
                    entry.LastProcessedIndex = item.LastProcessedIndex.Value;
                }
                entry.ConsecutiveFailureCount = item.ConsecutiveFailureCount < 0 ? 0 : item.ConsecutiveFailureCount;
                entry.CircuitOpenUntilUtc = item.CircuitOpenUntilUtc;
                entry.LastAttemptUtc = item.LastAttemptUtc;
                entry.LastSuccessUtc = item.LastSuccessUtc;
                entry.LastError = NormalizeError(item.LastError);
            }
        } catch {
            return new NativeCtCursorState();
        }

        return state;
    }

    public void Save(string? path) {
        if (string.IsNullOrWhiteSpace(path)) {
            return;
        }

        try {
            var fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory)) {
                Directory.CreateDirectory(directory);
            }

            NativeCtCursorStateDocument payload;
            lock (_sync) {
                payload = new NativeCtCursorStateDocument {
                    Version = 2,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    Entries = _entries
                        .Where(static kvp => !ContainsIgnoredLogUrl(kvp.Key))
                        .OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(kvp => new NativeCtCursorStateEntry {
                            Key = kvp.Key,
                            LastProcessedIndex = kvp.Value.LastProcessedIndex,
                            ConsecutiveFailureCount = kvp.Value.ConsecutiveFailureCount,
                            CircuitOpenUntilUtc = kvp.Value.CircuitOpenUntilUtc,
                            LastAttemptUtc = kvp.Value.LastAttemptUtc,
                            LastSuccessUtc = kvp.Value.LastSuccessUtc,
                            LastError = kvp.Value.LastError
                        })
                        .ToList()
                };
            }

            var json = JsonSerializer.Serialize(payload, JsonOptions.Default);
            File.WriteAllText(fullPath, json);
        } catch {
            // Best effort cursor persistence.
        }
    }

    private NativeCtCursorEntryState GetOrCreateEntry(string key) {
        if (!_entries.TryGetValue(key, out var entry)) {
            entry = new NativeCtCursorEntryState();
            _entries[key] = entry;
        }
        return entry;
    }

    private static bool ContainsIgnoredLogUrl(string key) {
        if (string.IsNullOrWhiteSpace(key)) {
            return false;
        }

        return key.Contains(KnownBogusCtLogUrlPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeError(string? value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return null;
        }

        var trimmed = value!.Trim();
        if (trimmed.Length > 512) {
            trimmed = trimmed.Substring(0, 512);
        }
        return trimmed;
    }

    private sealed class NativeCtCursorStateDocument {
        public int Version { get; set; }
        public DateTimeOffset UpdatedAtUtc { get; set; }
        public List<NativeCtCursorStateEntry> Entries { get; set; } = new();
    }

    private sealed class NativeCtCursorEntryState {
        public long? LastProcessedIndex { get; set; }
        public int ConsecutiveFailureCount { get; set; }
        public DateTimeOffset? CircuitOpenUntilUtc { get; set; }
        public DateTimeOffset? LastAttemptUtc { get; set; }
        public DateTimeOffset? LastSuccessUtc { get; set; }
        public string? LastError { get; set; }
    }

    private sealed class NativeCtCursorStateEntry {
        public string Key { get; set; } = string.Empty;
        public long? LastProcessedIndex { get; set; }
        public int ConsecutiveFailureCount { get; set; }
        public DateTimeOffset? CircuitOpenUntilUtc { get; set; }
        public DateTimeOffset? LastAttemptUtc { get; set; }
        public DateTimeOffset? LastSuccessUtc { get; set; }
        public string? LastError { get; set; }
    }
}

internal readonly record struct NativeCtCursorEntrySnapshot(
    long? LastProcessedIndex,
    int ConsecutiveFailureCount,
    DateTimeOffset? CircuitOpenUntilUtc,
    DateTimeOffset? LastAttemptUtc,
    DateTimeOffset? LastSuccessUtc,
    string? LastError);
