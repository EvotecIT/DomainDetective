using System;
using System.IO;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Shared helper methods for certificate inventory CLI commands.
/// </summary>
internal static class CertificateInventoryCommandHelpers {
    private static readonly char[] CsvSpecialChars = { ',', '"', '\r', '\n' };

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
}
