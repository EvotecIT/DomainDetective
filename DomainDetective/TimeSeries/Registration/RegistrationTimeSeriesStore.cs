using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DomainDetective.Helpers;

namespace DomainDetective.TimeSeries.Registration;

public sealed class RegistrationTimeSeriesStore
{
    private static readonly string[] SupportedExtensions = { ".json" };

    public RegistrationTimeSeriesStore(string rootPath)
    {
        RootPath = rootPath ?? throw new ArgumentNullException(nameof(rootPath));
    }

    public string RootPath { get; }

    public string GetDomainDirectory(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain is required.", nameof(domain));
        }

        var safeDomain = PathHelper.NormalizeDomainPathSegment(domain);
        return PathHelper.CombineUnderRoot(RootPath, "registration", safeDomain);
    }

    public string SaveSnapshot(RegistrationSnapshot snapshot)
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

    public IReadOnlyList<RegistrationSnapshot> LoadSnapshots(string domain, DateTimeOffset? sinceUtc = null)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return Array.Empty<RegistrationSnapshot>();
        }

        var dir = GetDomainDirectory(domain);
        if (!Directory.Exists(dir))
        {
            return Array.Empty<RegistrationSnapshot>();
        }

        var files = Directory.EnumerateFiles(dir)
            .Where(f => SupportedExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var list = new List<RegistrationSnapshot>();
        foreach (var file in files)
        {
            try
            {
                var json = File.ReadAllText(file, Encoding.UTF8);
                var snap = JsonSerializer.Deserialize<RegistrationSnapshot>(json, JsonOptions.Default);
                if (snap == null)
                {
                    continue;
                }
                if (sinceUtc.HasValue && snap.CapturedAtUtc < sinceUtc.Value)
                {
                    continue;
                }
                list.Add(snap);
            }
            catch
            {
                // Ignore invalid JSON snapshots
            }
        }

        return list
            .OrderBy(s => s.CapturedAtUtc)
            .ToList();
    }

    private static string BuildFileName(RegistrationSnapshot snapshot)
    {
        var datePart = snapshot.CapturedAtUtc.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);

        var ns = snapshot.NameServers != null && snapshot.NameServers.Count > 0
            ? string.Join(",", snapshot.NameServers.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            : string.Empty;
        var st = snapshot.Status != null && snapshot.Status.Count > 0
            ? string.Join(",", snapshot.Status.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            : string.Empty;

        var key = $"{snapshot.Domain}|{snapshot.HasRdap}|{snapshot.HasWhois}|{snapshot.Registrar}|{snapshot.RegistrarId}|{snapshot.CreatedAtUtc:O}|{snapshot.UpdatedAtUtc:O}|{snapshot.ExpiresAtUtc:O}|{snapshot.PrivacyProtected}|{snapshot.RegistrarLocked}|{ns}|{st}";
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

