using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using DnsClientX;
using DomainDetective;

namespace DomainDetective.Monitoring;

/// <summary>
/// Handles persistence and diffing of DNS propagation snapshots.
/// </summary>
public class DnsSnapshotManager
{
    /// <summary>Directory used to store snapshot files.</summary>
    public string? SnapshotDirectory { get; set; }

    /// <summary>Saves the provided results to a timestamped snapshot file.</summary>
    /// <param name="domain">Domain that was queried.</param>
    /// <param name="recordType">DNS record type.</param>
    /// <param name="results">Query results.</param>
    public void SaveSnapshot(string domain, DnsRecordType recordType, IEnumerable<DnsPropagationResult> results)
    {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(domain) || results == null)
        {
            return;
        }

        Directory.CreateDirectory(SnapshotDirectory);
        var file = BuildSnapshotPath(domain, recordType, DateTime.UtcNow);
        var json = JsonSerializer.Serialize(results, DomainHealthCheck.JsonOptions);
        File.WriteAllText(file, json, Encoding.UTF8);
    }

    /// <summary>Returns line level differences between <paramref name="results"/> and the latest snapshot.</summary>
    /// <param name="domain">Domain that was queried.</param>
    /// <param name="recordType">DNS record type.</param>
    /// <param name="results">Current query results.</param>
    public IEnumerable<string> GetSnapshotChanges(string domain, DnsRecordType recordType, IEnumerable<DnsPropagationResult> results)
    {
        if (string.IsNullOrEmpty(SnapshotDirectory) || string.IsNullOrEmpty(domain))
        {
            return Array.Empty<string>();
        }

        var safe = SanitizeDomain(domain);
        var files = Directory.GetFiles(SnapshotDirectory, $"{safe}_{recordType}_*.json");
        if (files.Length == 0)
        {
            return Array.Empty<string>();
        }

        var previousFile = files.OrderByDescending(f => f).First();
        var previousJson = File.ReadAllText(previousFile);
        var previousResults = JsonSerializer.Deserialize<List<DnsPropagationResult>>(previousJson, DomainHealthCheck.JsonOptions) ?? new List<DnsPropagationResult>();

        static string[] ToLines(IEnumerable<DnsPropagationResult> res) => res
            .OrderBy(r => r.Server.IPAddress.ToString())
            .Select(r => $"{r.Server.IPAddress}:{string.Join(",", r.Records ?? Array.Empty<string>())}")
            .ToArray();

        var prevLines = ToLines(previousResults);
        var currLines = ToLines(results);
        var max = Math.Max(prevLines.Length, currLines.Length);
        var changes = new List<string>();
        for (var i = 0; i < max; i++)
        {
            var prev = i < prevLines.Length ? prevLines[i] : string.Empty;
            var curr = i < currLines.Length ? currLines[i] : string.Empty;
            if (!string.Equals(prev, curr, StringComparison.Ordinal))
            {
                changes.Add("- " + prev);
                changes.Add("+ " + curr);
            }
        }
        return changes;
    }

    /// <summary>Builds a snapshot file path for the specified parameters.</summary>
    /// <param name="domain">Domain name.</param>
    /// <param name="recordType">DNS record type.</param>
    /// <param name="timestamp">Timestamp used in the file name.</param>
    /// <returns>Full file path for the snapshot.</returns>
    public string BuildSnapshotPath(string domain, DnsRecordType recordType, DateTime timestamp)
    {
        if (string.IsNullOrEmpty(SnapshotDirectory))
        {
            throw new InvalidOperationException("SnapshotDirectory is not set.");
        }

        var safe = SanitizeDomain(domain);
        return Path.Combine(SnapshotDirectory, $"{safe}_{recordType}_{timestamp:yyyyMMddHHmmss}.json");
    }

    private static string SanitizeDomain(string domain) => domain
        .Replace(Path.DirectorySeparatorChar, '-')
        .Replace(Path.AltDirectorySeparatorChar, '-');
}
