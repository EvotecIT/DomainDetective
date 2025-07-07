using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Generators;

[Generator]
/// <summary>
/// Generates enums mapping countries and locations based on the PublicDNS.json additional file.
/// </summary>
public sealed class CountryLocationGenerator : ISourceGenerator {
    /// <inheritdoc/>
    public void Initialize(GeneratorInitializationContext context) {
    }

    /// <inheritdoc/>
    public void Execute(GeneratorExecutionContext context) {
        var file = context.AdditionalFiles.FirstOrDefault(f => f.Path.EndsWith("PublicDNS.json"));
        if (file == null) {
            return;
        }
        var text = file.GetText(context.CancellationToken);
        if (text == null) {
            return;
        }
        var json = text.ToString();
        if (json.Length == 0) {
            return;
        }
        using var doc = JsonDocument.Parse(json);
        var countries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var locations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var element in doc.RootElement.EnumerateArray()) {
            if (element.TryGetProperty("Country", out var c)) {
                var val = c.GetString()?.Trim();
                if (!string.IsNullOrWhiteSpace(val)) {
                    countries.Add(val);
                }
            }
            if (element.TryGetProperty("Location", out var l)) {
                var val = l.GetString()?.Trim();
                if (!string.IsNullOrWhiteSpace(val)) {
                    locations.Add(val);
                }
            }
        }
        var countryMap = BuildMap(countries);
        var locationMap = BuildMap(locations);
        var sb = new StringBuilder();
        sb.AppendLine("using System;");
        sb.AppendLine("using System.Collections.Generic;");
        sb.AppendLine("#nullable enable");
        sb.AppendLine("namespace DomainDetective;");
        sb.AppendLine("public enum CountryId { ");
        foreach (var id in countryMap.Keys.OrderBy(k => k)) {
            sb.AppendLine($"    {id},");
        }
        sb.AppendLine("}");
        sb.AppendLine("public enum LocationId { ");
        foreach (var id in locationMap.Keys.OrderBy(k => k)) {
            sb.AppendLine($"    {id},");
        }
        sb.AppendLine("}");
        sb.AppendLine("public static partial class CountryIdExtensions {");
        sb.AppendLine("    private static readonly Dictionary<string, CountryId> _map = new(StringComparer.OrdinalIgnoreCase) {");
        foreach (var kvp in countryMap) {
            sb.AppendLine($"        [\"{kvp.Value}\"] = CountryId.{kvp.Key},");
        }
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static string ToName(this CountryId id) => id switch {");
        foreach (var kvp in countryMap) {
            sb.AppendLine($"        CountryId.{kvp.Key} => \"{kvp.Value}\",");
        }
        sb.AppendLine("        _ => string.Empty");
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static bool TryParse(string? name, out CountryId id) {");
        sb.AppendLine("        if (!string.IsNullOrWhiteSpace(name) && _map.TryGetValue(name.Trim(), out id)) { return true; }\n        id = default; return false; }");
        sb.AppendLine("}");
        sb.AppendLine("public static partial class LocationIdExtensions {");
        sb.AppendLine("    private static readonly Dictionary<string, LocationId> _map = new(StringComparer.OrdinalIgnoreCase) {");
        foreach (var kvp in locationMap) {
            sb.AppendLine($"        [\"{kvp.Value}\"] = LocationId.{kvp.Key},");
        }
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static string ToName(this LocationId id) => id switch {");
        foreach (var kvp in locationMap) {
            sb.AppendLine($"        LocationId.{kvp.Key} => \"{kvp.Value}\",");
        }
        sb.AppendLine("        _ => string.Empty");
        sb.AppendLine("    };\n");
        sb.AppendLine("    public static bool TryParse(string? name, out LocationId id) {");
        sb.AppendLine("        if (!string.IsNullOrWhiteSpace(name) && _map.TryGetValue(name.Trim(), out id)) { return true; }\n        id = default; return false; }");
        sb.AppendLine("}");

        context.AddSource("CountryLocationEnums.g.cs", SourceText.From(sb.ToString(), Encoding.UTF8));
    }

    private static Dictionary<string, string> BuildMap(IEnumerable<string> names) {
        var map = new Dictionary<string, string>();
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
}
