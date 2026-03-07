using System;
using System.Collections.Generic;
using System.Globalization;

namespace DomainDetective {
    internal static class CertificateInventoryNativeCtDiagnosticsParsing {
        internal static IReadOnlyList<NativeCtLogDiagnosticEntry> ResolveDiagnostics(CertificateInventorySnapshot snapshot) {
            var list = snapshot.NativeCtLogDiagnostics ?? new List<NativeCtLogDiagnosticEntry>();
            if (list.Count > 0) {
                return list;
            }

            var raw = snapshot.NativeCtLogDiagnosticsRaw ?? new List<string>();
            if (raw.Count == 0) {
                return Array.Empty<NativeCtLogDiagnosticEntry>();
            }

            var parsed = new List<NativeCtLogDiagnosticEntry>(raw.Count);
            foreach (var line in raw) {
                if (TryParseRawDiagnostic(line, out var entry) && entry != null) {
                    parsed.Add(entry);
                }
            }
            return parsed;
        }

        internal static bool TryParseRawDiagnostic(string? line, out NativeCtLogDiagnosticEntry? entry) {
            entry = null;
            if (string.IsNullOrWhiteSpace(line)) {
                return false;
            }

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var parts = line!.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.Length == 0) {
                    continue;
                }

                var equalsIndex = trimmed.IndexOf('=');
                if (equalsIndex <= 0 || equalsIndex >= trimmed.Length - 1) {
                    continue;
                }

                var key = trimmed.Substring(0, equalsIndex).Trim();
                var value = trimmed.Substring(equalsIndex + 1).Trim();
                map[key] = value;
            }

            if (!map.TryGetValue("log", out var logUrl) || string.IsNullOrWhiteSpace(logUrl)) {
                return false;
            }

            map.TryGetValue("scope", out var scope);
            map.TryGetValue("state", out var state);
            map.TryGetValue("failure", out var failure);

            entry = new NativeCtLogDiagnosticEntry {
                Scope = scope ?? string.Empty,
                State = NormalizeState(state),
                LogUrl = logUrl,
                TreeSize = ParseLong(map, "tree"),
                LastProcessedIndex = ParseLong(map, "last"),
                LagBefore = ParseLong(map, "lagBefore"),
                LagAfter = ParseLong(map, "lagAfter"),
                CircuitOpenUntilUtc = ParseUtc(map, "circuitUntil"),
                Failure = NormalizeStringValue(failure),
                SharedIngestion = ParseBool(map, "shared")
            };
            return true;
        }

        internal static string NormalizeState(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return "Unknown";
            }

            var state = value!.Trim();
            if (state.Equals("circuitopen", StringComparison.OrdinalIgnoreCase)) {
                return "CircuitOpen";
            }
            if (state.Equals("succeeded", StringComparison.OrdinalIgnoreCase)) {
                return "Succeeded";
            }
            if (state.Equals("failed", StringComparison.OrdinalIgnoreCase)) {
                return "Failed";
            }
            return state;
        }

        private static long? ParseLong(IReadOnlyDictionary<string, string> map, string key) {
            if (!map.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value) || value == "-") {
                return null;
            }

            if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)) {
                return number;
            }

            return null;
        }

        private static DateTimeOffset? ParseUtc(IReadOnlyDictionary<string, string> map, string key) {
            if (!map.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value) || value == "-") {
                return null;
            }

            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)) {
                return parsed;
            }

            return null;
        }

        private static bool ParseBool(IReadOnlyDictionary<string, string> map, string key) {
            if (!map.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value)) {
                return false;
            }

            return bool.TryParse(value, out var parsed) && parsed;
        }

        private static string? NormalizeStringValue(string? value) {
            if (string.IsNullOrWhiteSpace(value) || value == "-") {
                return null;
            }

            var normalized = value!.Trim();
            return normalized.Length == 0 ? null : normalized;
        }
    }
}
