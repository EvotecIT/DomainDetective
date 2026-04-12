using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DomainDetective.Helpers;

namespace DomainDetective.TimeSeries.TlsRpt;

/// <summary>Provides tls rpt time series store functionality.</summary>
public sealed class TlsRptTimeSeriesStore
{
    private static readonly string[] SupportedExtensions = { ".json" };

    /// <summary>Initializes a new instance of the TlsRptTimeSeriesStore class.</summary>
    public TlsRptTimeSeriesStore(string rootPath)
    {
        RootPath = rootPath ?? throw new ArgumentNullException(nameof(rootPath));
    }

    /// <summary>Gets the root path value.</summary>
    public string RootPath { get; }

    /// <summary>Gets domain directory.</summary>
    public string GetDomainDirectory(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain is required.", nameof(domain));
        }

        var safeDomain = PathHelper.NormalizeDomainPathSegment(domain);
        return PathHelper.CombineUnderRoot(RootPath, "tls-rpt", safeDomain);
    }

    /// <summary>Saves snapshot.</summary>
    public string SaveSnapshot(TlsRptSnapshot snapshot)
    {
        if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
        if (string.IsNullOrWhiteSpace(snapshot.Domain)) throw new ArgumentException("Snapshot.Domain is required.", nameof(snapshot));

        var dir = GetDomainDirectory(snapshot.Domain);
        Directory.CreateDirectory(dir);

        var file = Path.Combine(dir, BuildFileName(snapshot));
        if (File.Exists(file))
        {
            return file;
        }

        var json = JsonSerializer.Serialize(snapshot, JsonOptions.Default);
        File.WriteAllText(file, json, Encoding.UTF8);
        return file;
    }

    /// <summary>Loads snapshots.</summary>
    public IReadOnlyList<TlsRptSnapshot> LoadSnapshots(string domain, DateTimeOffset? sinceUtc = null)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return Array.Empty<TlsRptSnapshot>();
        }

        var dir = GetDomainDirectory(domain);
        if (!Directory.Exists(dir))
        {
            return Array.Empty<TlsRptSnapshot>();
        }

        var files = Directory.EnumerateFiles(dir)
            .Where(f => SupportedExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var list = new List<TlsRptSnapshot>();
        foreach (var file in files)
        {
            try
            {
                var json = File.ReadAllText(file, Encoding.UTF8);
                var snap = JsonSerializer.Deserialize<TlsRptSnapshot>(json, JsonOptions.Default);
                if (snap == null)
                {
                    continue;
                }

                if (sinceUtc.HasValue)
                {
                    var pivot = snap.RangeEndUtc ?? snap.IngestedAtUtc;
                    if (pivot < sinceUtc.Value)
                    {
                        continue;
                    }
                }

                list.Add(snap);
            }
            catch
            {
                // Ignore invalid JSON snapshots
            }
        }

        return list;
    }

    private static string BuildFileName(TlsRptSnapshot snapshot)
    {
        var end = snapshot.RangeEndUtc ?? snapshot.IngestedAtUtc;
        var datePart = end.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

        var key = $"{snapshot.Domain}|{snapshot.ReportId}|{snapshot.RangeBeginUtc:O}|{snapshot.RangeEndUtc:O}|{snapshot.ReporterOrgName}|{snapshot.TotalSuccessfulSessions}|{snapshot.TotalFailedSessions}";
        var hash = ComputeStableHashHex(key).Substring(0, 12);
        return $"{datePart}_{hash}.json";
    }

    private static string ComputeStableHashHex(string value)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        var hash = sha.ComputeHash(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash)
        {
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }
}

