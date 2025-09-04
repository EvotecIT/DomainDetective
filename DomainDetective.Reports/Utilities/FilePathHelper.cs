using System.IO;
using System.Text;

namespace DomainDetective.Reports;

public static class FilePathHelper
{
    public static string MakeFileSafe(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input) sb.Append(System.Array.IndexOf(invalid, ch) >= 0 ? '_' : ch);
        return sb.ToString();
    }

    public static string ResolveBaseDirectory(string? exportPath, string? defaultOutputDirectory)
    {
        if (!string.IsNullOrWhiteSpace(exportPath))
        {
            try { var d = Path.GetDirectoryName(exportPath); if (!string.IsNullOrWhiteSpace(d)) return d!; } catch { }
        }
        if (!string.IsNullOrWhiteSpace(defaultOutputDirectory))
        {
            return defaultOutputDirectory!;
        }
        return Directory.GetCurrentDirectory();
    }
}

