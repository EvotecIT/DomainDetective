using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.CLI;

internal static class RecentDomains
{
    private const int MaxEntries = 20;
    private static string GetStorePath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(appData)) appData = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var dir = Path.Combine(appData, "DomainDetective");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "recent_domains.json");
    }

    public static List<string> Load()
    {
        try
        {
            var path = GetStorePath();
            if (!File.Exists(path)) return new List<string>();
            var json = File.ReadAllText(path);
            var list = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            return list.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxEntries).ToList();
        }
        catch { return new List<string>(); }
    }

    private static void Save(List<string> items)
    {
        try
        {
            var path = GetStorePath();
            var json = JsonSerializer.Serialize(items.Take(MaxEntries).ToList(), new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
        catch { /* ignore */ }
    }

    public static void Add(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        var items = Load();
        items.RemoveAll(d => string.Equals(d, domain, StringComparison.OrdinalIgnoreCase));
        items.Insert(0, domain);
        Save(items);
    }
}

