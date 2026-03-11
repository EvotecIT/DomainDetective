using System;
using System.Collections.Generic;
using System.IO;

namespace DomainDetective.Reports;

public static class ReportPathHelper
{
    private static string GetExtension(ReportFormat format)
    {
        return format switch
        {
            ReportFormat.Html => ".html",
            ReportFormat.Word => ".docx",
            ReportFormat.Excel => ".xlsx",
            ReportFormat.Pdf => ".pdf",
            ReportFormat.Json => ".json",
            ReportFormat.Markdown => ".md",
            ReportFormat.MarkdownHtml => ".html",
            _ => ".html"
        };
    }

    public static string ResolveOutputPath(string? explicitPath, string? defaultOutputDirectory, string subject, ReportFormat format)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            try
            {
                var p = explicitPath!;
                var looksLikeDirectory = false;
                if (Directory.Exists(p)) looksLikeDirectory = true;
                else if (p.EndsWith(Path.DirectorySeparatorChar.ToString()) || p.EndsWith(Path.AltDirectorySeparatorChar.ToString())) looksLikeDirectory = true;
                else if (!Path.HasExtension(p)) looksLikeDirectory = true;

                if (looksLikeDirectory)
                {
                    // Generate a default file name under this directory
                    return GenerateDefaultPath(subject, format, p);
                }

                EnsureParentDirectoryExists(p);
                return p;
            }
            catch
            {
                // Fall back to default path generation
                return GenerateDefaultPath(subject, format, defaultOutputDirectory);
            }
        }
        return GenerateDefaultPath(subject, format, defaultOutputDirectory);
    }

    public static string ResolveOutputPathForFormat(string? explicitPath, string? defaultOutputDirectory, string subject, ReportFormat format, IReadOnlyList<ReportFormat>? allFormats = null)
    {
        var formats = allFormats ?? new[] { format };
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            try
            {
                var p = explicitPath!;
                var looksLikeDirectory = false;
                if (Directory.Exists(p)) looksLikeDirectory = true;
                else if (p.EndsWith(Path.DirectorySeparatorChar.ToString()) || p.EndsWith(Path.AltDirectorySeparatorChar.ToString())) looksLikeDirectory = true;
                else if (!Path.HasExtension(p)) looksLikeDirectory = true;

                if (!looksLikeDirectory && formats.Count > 1)
                {
                    var dir = Path.GetDirectoryName(p) ?? string.Empty;
                    var name = Path.GetFileNameWithoutExtension(p);
                    var ext = GetExtension(format);
                    var combined = Path.Combine(string.IsNullOrEmpty(dir) ? "." : dir, name + ext);
                    try { Directory.CreateDirectory(string.IsNullOrEmpty(dir) ? "." : dir); } catch { }
                    return combined;
                }

                if (!looksLikeDirectory)
                {
                    var currentExtension = Path.GetExtension(p);
                    var expectedExtension = GetExtension(format);
                    if (!string.IsNullOrWhiteSpace(currentExtension) &&
                        !string.Equals(currentExtension, expectedExtension, StringComparison.OrdinalIgnoreCase))
                    {
                        var dir = Path.GetDirectoryName(p) ?? string.Empty;
                        var name = Path.GetFileNameWithoutExtension(p);
                        var combined = Path.Combine(string.IsNullOrEmpty(dir) ? "." : dir, name + expectedExtension);
                        try { Directory.CreateDirectory(string.IsNullOrEmpty(dir) ? "." : dir); } catch { }
                        return combined;
                    }
                }
            }
            catch
            {
                return ResolveOutputPath(explicitPath, defaultOutputDirectory, subject, format);
            }
        }

        return ResolveOutputPath(explicitPath, defaultOutputDirectory, subject, format);
    }

    public static void EnsureParentDirectoryExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }
        }
        catch
        {
            // Best-effort only. Callers can still handle write failures.
        }
    }

    public static string GenerateDefaultPath(string subject, ReportFormat format, string? outputDirectory)
    {
        var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var safe = (subject ?? "domain").Replace('.', '_');
        var ext = GetExtension(format).TrimStart('.');
        var file = $"{safe}_{ts}.{ext}";
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            try
            {
                Directory.CreateDirectory(outputDirectory!);
                return Path.Combine(outputDirectory!, file);
            }
            catch { /* fall back */ }
        }
        return file;
    }
}
