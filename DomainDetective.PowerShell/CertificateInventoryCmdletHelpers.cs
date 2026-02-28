using System;
using System.IO;

namespace DomainDetective.PowerShell;

/// <summary>
/// Shared helpers used by certificate inventory PowerShell cmdlets.
/// </summary>
internal static class CertificateInventoryCmdletHelpers {
    internal static string ResolveCacheDirectory(string? configured) {
        if (!string.IsNullOrWhiteSpace(configured)) {
            return configured!;
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
}
