using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using DomainDetective.Helpers;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Shared helper methods for certificate inventory CLI commands.
/// </summary>
internal static class CertificateInventoryCommandHelpers {
    private static readonly char[] CsvSpecialChars = { ',', '"', '\r', '\n' };
    private static readonly JsonSerializerOptions NdjsonOptions = new(JsonOptions.Default) {
        WriteIndented = false
    };

    internal static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured;
        }

        return Path.Combine(Path.GetTempPath(), "DomainDetective", "cert-monitor");
    }

    internal static DateTimeOffset? ToUtc(DateTime? value) {
        if (!value.HasValue) {
            return null;
        }

        var dt = value.Value;
        if (dt.Kind == DateTimeKind.Unspecified) {
            dt = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
        }

        return dt.ToUniversalTime();
    }

    internal static string EscapeCsv(string? value) {
        var text = value ?? string.Empty;
        if (text.IndexOfAny(CsvSpecialChars) >= 0) {
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        return text;
    }

    internal static void WriteUtf8Text(string fullPath, string content) {
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        if (fullPath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) {
            using (var fileStream = new FileStream(fullPath, FileMode.Create, FileAccess.Write, FileShare.None)) {
                using (var gzipStream = new GZipStream(fileStream, CompressionLevel.Optimal)) {
                    using (var writer = new StreamWriter(gzipStream, new UTF8Encoding(true))) {
                        writer.Write(content);
                    }
                }
            }
            return;
        }

        File.WriteAllText(fullPath, content, Encoding.UTF8);
    }

    internal static string SerializeJsonLine<T>(T value) {
        return JsonSerializer.Serialize(value, NdjsonOptions);
    }
}
