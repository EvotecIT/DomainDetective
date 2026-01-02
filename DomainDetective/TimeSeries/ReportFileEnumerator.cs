using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DomainDetective.TimeSeries;

internal static class ReportFileEnumerator
{
    internal static IEnumerable<string> EnumerateFiles(string input, IReadOnlyCollection<string> extensions)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return Array.Empty<string>();
        }

        var exts = new HashSet<string>(extensions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

        if (Directory.Exists(input))
        {
            return Directory.EnumerateFiles(input)
                .Where(f => exts.Contains(Path.GetExtension(f)));
        }

        if (input.IndexOf('*') >= 0 || input.IndexOf('?') >= 0)
        {
            var dir = Path.GetDirectoryName(input);
            var pat = Path.GetFileName(input);
            if (string.IsNullOrEmpty(dir))
            {
                dir = ".";
            }
            var matches = Directory.EnumerateFiles(dir, pat);
            return matches.Where(f => exts.Contains(Path.GetExtension(f)));
        }

        if (File.Exists(input) && exts.Contains(Path.GetExtension(input)))
        {
            return new[] { input };
        }

        return Array.Empty<string>();
    }
}

