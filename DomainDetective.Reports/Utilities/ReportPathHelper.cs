using System;
using System.IO;

namespace DomainDetective.Reports;

public static class ReportPathHelper
{
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

    public static string GenerateDefaultPath(string subject, ReportFormat format, string? outputDirectory)
    {
        var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var safe = (subject ?? "domain").Replace('.', '_');
        var ext = format switch
        {
            ReportFormat.Html => "html",
            ReportFormat.Word => "docx",
            ReportFormat.Excel => "xlsx",
            ReportFormat.Pdf => "pdf",
            ReportFormat.Json => "json",
            ReportFormat.Markdown => "md",
            ReportFormat.MarkdownHtml => "html",
            _ => "html"
        };
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
