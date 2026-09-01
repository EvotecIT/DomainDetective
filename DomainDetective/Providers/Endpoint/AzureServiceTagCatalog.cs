using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace DomainDetective.Providers.Endpoint;

/// <summary>One Azure service tag and its published address prefixes.</summary>
public sealed class AzureServiceTagEntry {
    /// <summary>Published service-tag name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Tag-specific change number from the source catalog.</summary>
    public string ChangeNumber { get; init; } = string.Empty;

    /// <summary>Azure region associated with the tag, when present.</summary>
    public string Region { get; init; } = string.Empty;

    /// <summary>System service associated with the tag, when present.</summary>
    public string SystemService { get; init; } = string.Empty;

    /// <summary>Parsed IPv4 and IPv6 address prefixes.</summary>
    public IReadOnlyList<IpCidrRange> AddressPrefixes { get; init; } = Array.Empty<IpCidrRange>();
}

/// <summary>
/// Parses and queries Microsoft Azure service-tag JSON without embedding time-sensitive ranges.
/// </summary>
public sealed class AzureServiceTagCatalog {
    private readonly Dictionary<string, AzureServiceTagEntry> _entries;

    private AzureServiceTagCatalog(
        string cloud,
        string changeNumber,
        string source,
        DateTimeOffset retrievedAtUtc,
        IEnumerable<AzureServiceTagEntry> entries) {
        Cloud = cloud;
        ChangeNumber = changeNumber;
        Source = source;
        RetrievedAtUtc = retrievedAtUtc;
        try {
            _entries = entries.ToDictionary(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        } catch (ArgumentException ex) {
            throw new FormatException("Azure service-tag JSON contains duplicate service-tag names.", ex);
        }
    }

    /// <summary>Cloud name reported by the source catalog.</summary>
    public string Cloud { get; }

    /// <summary>Catalog-wide change number.</summary>
    public string ChangeNumber { get; }

    /// <summary>Caller-provided source identifier, such as a file path or discovery API URL.</summary>
    public string Source { get; }

    /// <summary>Time at which the caller retrieved or loaded the catalog.</summary>
    public DateTimeOffset RetrievedAtUtc { get; }

    /// <summary>All parsed service tags.</summary>
    public IReadOnlyCollection<AzureServiceTagEntry> Entries => _entries.Values;

    /// <summary>Loads a service-tag catalog from a JSON file.</summary>
    public static AzureServiceTagCatalog LoadFile(
        string path,
        DateTimeOffset? retrievedAtUtc = null) {
        if (string.IsNullOrWhiteSpace(path)) {
            throw new ArgumentNullException(nameof(path));
        }
        string json = File.ReadAllText(path);
        return Parse(json, path, retrievedAtUtc);
    }

    /// <summary>Parses downloadable or Service Tag Discovery API JSON.</summary>
    public static AzureServiceTagCatalog Parse(
        string json,
        string source = "azure-service-tags-json",
        DateTimeOffset? retrievedAtUtc = null) {
        if (string.IsNullOrWhiteSpace(json)) {
            throw new ArgumentNullException(nameof(json));
        }

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) {
            throw new FormatException("Azure service-tag JSON root must be an object.");
        }
        string cloud = ReadScalar(root, "cloud");
        string changeNumber = ReadScalar(root, "changeNumber");
        var entries = new List<AzureServiceTagEntry>();

        if (!root.TryGetProperty("values", out JsonElement values) || values.ValueKind != JsonValueKind.Array) {
            throw new FormatException("Azure service-tag JSON does not contain a values array.");
        }

        int itemIndex = -1;
        foreach (JsonElement item in values.EnumerateArray()) {
            itemIndex++;
            if (item.ValueKind != JsonValueKind.Object) {
                throw new FormatException(
                    $"Azure service-tag JSON values[{itemIndex}] must be an object.");
            }
            string name = ReadScalar(item, "name");
            if (string.IsNullOrWhiteSpace(name)) {
                continue;
            }

            if (!item.TryGetProperty("properties", out JsonElement properties) ||
                properties.ValueKind != JsonValueKind.Object) {
                throw new FormatException(
                    $"Azure service tag '{name}' must contain a properties object.");
            }

            var prefixes = new List<IpCidrRange>();
            if (properties.TryGetProperty("addressPrefixes", out JsonElement addressPrefixes)) {
                if (addressPrefixes.ValueKind != JsonValueKind.Array) {
                    throw new FormatException(
                        $"Azure service tag '{name}' contains an addressPrefixes field that is not an array.");
                }
                foreach (JsonElement prefixElement in addressPrefixes.EnumerateArray()) {
                    if (prefixElement.ValueKind != JsonValueKind.String) {
                        throw new FormatException(
                            $"Azure service tag '{name}' contains a non-string address prefix value.");
                    }
                    string prefixText = prefixElement.GetString() ?? string.Empty;
                    try {
                        prefixes.Add(IpCidrRange.Parse(prefixText));
                    } catch (FormatException ex) {
                        throw new FormatException(
                            $"Azure service tag '{name}' contains invalid address prefix '{prefixText}'.",
                            ex);
                    }
                }
            }

            entries.Add(new AzureServiceTagEntry {
                Name = name,
                ChangeNumber = ReadScalar(properties, "changeNumber"),
                Region = ReadScalar(properties, "region"),
                SystemService = ReadScalar(properties, "systemService"),
                AddressPrefixes = prefixes
            });
        }

        return new AzureServiceTagCatalog(
            cloud,
            changeNumber,
            source,
            retrievedAtUtc ?? DateTimeOffset.UtcNow,
            entries);
    }

    /// <summary>Returns true when a tag exists in this catalog.</summary>
    public bool TryGetTag(string name, out AzureServiceTagEntry? entry) {
        if (string.IsNullOrWhiteSpace(name)) {
            entry = null;
            return false;
        }
        return _entries.TryGetValue(name.Trim(), out entry);
    }

    /// <summary>Returns service-tag names containing the supplied address.</summary>
    public IReadOnlyList<string> FindTags(IPAddress address, IEnumerable<string>? candidateTagNames = null) {
        if (address == null) {
            throw new ArgumentNullException(nameof(address));
        }

        IEnumerable<AzureServiceTagEntry> candidates = _entries.Values;
        if (candidateTagNames != null) {
            var requested = new HashSet<string>(
                candidateTagNames.Where(name => !string.IsNullOrWhiteSpace(name)).Select(name => name.Trim()),
                StringComparer.OrdinalIgnoreCase);
            candidates = candidates.Where(entry => requested.Contains(entry.Name));
        }

        return candidates
            .Where(entry => entry.AddressPrefixes.Any(prefix => prefix.Contains(address)))
            .Select(entry => entry.Name)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ReadScalar(JsonElement element, string propertyName) {
        if (!element.TryGetProperty(propertyName, out JsonElement property)) {
            return string.Empty;
        }
        return property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? string.Empty
            : property.ToString();
    }
}
