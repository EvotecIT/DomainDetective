using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Generators;

[Generator]
/// <summary>
/// Generates enums mapping countries and locations based on the PublicDNS.json additional file.
/// </summary>
public sealed class CountryLocationGenerator : IIncrementalGenerator {
    /// <inheritdoc/>
    public void Initialize(IncrementalGeneratorInitializationContext context) {
        var modelProvider = context.AdditionalTextsProvider
            .Where(static file => string.Equals(Path.GetFileName(file.Path), "PublicDNS.json", StringComparison.OrdinalIgnoreCase))
            .Select(static (file, cancellationToken) => file.GetText(cancellationToken)?.ToString() ?? string.Empty)
            .Where(static json => !string.IsNullOrWhiteSpace(json))
            .Collect()
            .Select(static (jsonFiles, _) => CreateModel(jsonFiles));

        context.RegisterSourceOutput(modelProvider, static (productionContext, model) => {
            if (model == null) {
                return;
            }

            productionContext.AddSource("CountryLocationEnums.g.cs", SourceText.From(BuildSource(model), Encoding.UTF8));
        });
    }

    private static CountryLocationModel? CreateModel(ImmutableArray<string> jsonFiles) {
        foreach (var candidate in jsonFiles) {
            var json = candidate ?? string.Empty;
            if (string.IsNullOrWhiteSpace(json)) {
                continue;
            }

            try {
                using var document = JsonDocument.Parse(json);
                if (document.RootElement.ValueKind != JsonValueKind.Array) {
                    continue;
                }

                var countries = new List<string>();
                var locations = new List<string>();
                var seenCountries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var seenLocations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var element in document.RootElement.EnumerateArray()) {
                    AddValue(element, "Country", countries, seenCountries);
                    AddValue(element, "Location", locations, seenLocations);
                }

                return new CountryLocationModel(BuildMap(countries), BuildMap(locations));
            } catch (JsonException) {
                return null;
            }
        }

        return null;
    }

    private static void AddValue(JsonElement element, string propertyName, List<string> values, HashSet<string> seenValues) {
        if (!element.TryGetProperty(propertyName, out var property)) {
            return;
        }

        var value = property.GetString();
        if (value == null) {
            return;
        }

        var trimmedValue = value.Trim() ?? string.Empty;
        if (trimmedValue.Length == 0) {
            return;
        }

        if (seenValues.Add(trimmedValue)) {
            values.Add(trimmedValue);
        }
    }

    private static string BuildSource(CountryLocationModel model) {
        var sb = new StringBuilder();
        sb.AppendLine("using System;");
        sb.AppendLine("using System.Collections.Generic;");
        sb.AppendLine("#nullable enable");
        sb.AppendLine("namespace DomainDetective;");
        sb.AppendLine("public enum CountryId { ");
        foreach (var id in model.CountryMap.Keys.OrderBy(static key => key, StringComparer.Ordinal)) {
            sb.AppendLine($"    {id},");
        }
        sb.AppendLine("}");
        sb.AppendLine("public enum LocationId { ");
        foreach (var id in model.LocationMap.Keys.OrderBy(static key => key, StringComparer.Ordinal)) {
            sb.AppendLine($"    {id},");
        }
        sb.AppendLine("}");
        sb.AppendLine("public static partial class CountryIdExtensions {");
        sb.AppendLine("    private static readonly Dictionary<string, CountryId> _map = new(StringComparer.OrdinalIgnoreCase) {");
        foreach (var kvp in model.CountryMap) {
            sb.AppendLine($"        [\"{kvp.Value}\"] = CountryId.{kvp.Key},");
        }
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static string ToName(this CountryId id) => id switch {");
        foreach (var kvp in model.CountryMap) {
            sb.AppendLine($"        CountryId.{kvp.Key} => \"{kvp.Value}\",");
        }
        sb.AppendLine("        _ => string.Empty");
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static bool TryParse(string? name, out CountryId id) {");
        sb.AppendLine("        if (name != null && !string.IsNullOrWhiteSpace(name) && _map.TryGetValue(name.Trim(), out id)) { return true; }\n        id = default; return false; }");
        sb.AppendLine("}");
        sb.AppendLine("public static partial class LocationIdExtensions {");
        sb.AppendLine("    private static readonly Dictionary<string, LocationId> _map = new(StringComparer.OrdinalIgnoreCase) {");
        foreach (var kvp in model.LocationMap) {
            sb.AppendLine($"        [\"{kvp.Value}\"] = LocationId.{kvp.Key},");
        }
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static string ToName(this LocationId id) => id switch {");
        foreach (var kvp in model.LocationMap) {
            sb.AppendLine($"        LocationId.{kvp.Key} => \"{kvp.Value}\",");
        }
        sb.AppendLine("        _ => string.Empty");
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static bool TryParse(string? name, out LocationId id) {");
        sb.AppendLine("        if (name != null && !string.IsNullOrWhiteSpace(name) && _map.TryGetValue(name.Trim(), out id)) { return true; }\n        id = default; return false; }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static Dictionary<string, string> BuildMap(IEnumerable<string> names) {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in names) {
            var id = Sanitize(name);
            if (!map.ContainsKey(id)) {
                map[id] = name;
            }
        }
        return map;
    }

    private static string Sanitize(string value) {
        var sb = new StringBuilder();
        var nextUpper = true;
        foreach (var ch in value) {
            if (char.IsLetterOrDigit(ch)) {
                sb.Append(nextUpper ? char.ToUpperInvariant(ch) : ch);
                nextUpper = false;
            } else {
                nextUpper = true;
            }
        }
        if (sb.Length == 0 || char.IsDigit(sb[0])) {
            sb.Insert(0, '_');
        }
        return sb.ToString();
    }

    private sealed class CountryLocationModel {
        internal CountryLocationModel(Dictionary<string, string> countryMap, Dictionary<string, string> locationMap) {
            CountryMap = countryMap;
            LocationMap = locationMap;
        }

        internal Dictionary<string, string> CountryMap { get; }
        internal Dictionary<string, string> LocationMap { get; }
    }
}
