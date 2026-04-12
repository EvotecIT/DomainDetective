using System;
using System.IO;
using System.Linq;

namespace DomainDetective.Helpers;

/// <summary>Provides path helper functionality.</summary>
public static class PathHelper
{
    /// <summary>Executes the combine under root operation.</summary>
    public static string CombineUnderRoot(string rootPath, params string[] segments)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentNullException(nameof(rootPath));
        }

        var rootFull = Path.GetFullPath(rootPath);
        var combined = segments != null && segments.Length > 0
            ? Path.Combine(new[] { rootFull }.Concat(segments).ToArray())
            : rootFull;

        var combinedFull = Path.GetFullPath(combined);

        var comparison =
#if NET8_0_OR_GREATER
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
#else
            StringComparison.OrdinalIgnoreCase;
#endif

        var rootPrefix = rootFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!combinedFull.StartsWith(rootPrefix, comparison) && !string.Equals(combinedFull, rootFull, comparison))
        {
            throw new InvalidOperationException("Path traversal detected. The resolved path escapes the configured root directory.");
        }

        return combinedFull;
    }

    /// <summary>Executes the normalize domain path segment operation.</summary>
    public static string NormalizeDomainPathSegment(string domain)
        => DomainHelper.ValidateIdn(domain);
}
