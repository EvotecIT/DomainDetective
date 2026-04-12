using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Shared helpers for normalizing typosquatting mail-exchanger infrastructure.
/// </summary>
public static class TyposquattingMailInfrastructure
{
    /// <summary>Executes the normalize mx hosts operation.</summary>
    public static IReadOnlyList<string> NormalizeMxHosts(IEnumerable<string>? mxRecords)
    {
        if (mxRecords == null)
        {
            return Array.Empty<string>();
        }

        return mxRecords
            .Select(static record => ExtractMxHost(record))
            .Where(static host => !string.IsNullOrWhiteSpace(host))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static host => host, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>Executes the extract mx host operation.</summary>
    public static string ExtractMxHost(string? record)
    {
        if (string.IsNullOrWhiteSpace(record))
        {
            return string.Empty;
        }

        var parts = record!
            .Trim()
            .TrimEnd('.')
            .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return string.Empty;
        }

        var lastPart = parts[parts.Length - 1];
        return lastPart.Trim().TrimEnd('.').ToLowerInvariant();
    }
}
