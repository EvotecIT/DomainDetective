using DomainDetective.Toolbox.Models;
using DomainDetective.Toolbox.Services;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective.Website.Tests;

/// <summary>
/// The static website renders the tools hub and every tool route from Website/data/tools-catalog.json.
/// These tests keep that file identical to <see cref="ToolRegistry"/> so the static pages and the
/// WebAssembly tools can never disagree. Set DD_UPDATE_TOOL_CATALOG=1 and run the tests to regenerate it.
/// </summary>
public sealed class ToolCatalogTests {
    private static readonly JsonSerializerOptions JsonOptions = new() {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly ToolCategory[] CategoryOrder = {
        ToolCategory.Overview,
        ToolCategory.EmailSecurity,
        ToolCategory.Dns,
        ToolCategory.TlsCert,
        ToolCategory.WebSecurity,
        ToolCategory.ThreatIntel,
        ToolCategory.Registration,
        ToolCategory.WebDiscovery,
        ToolCategory.Subdomain,
        ToolCategory.Network
    };

    [Fact]
    public void CatalogFileMatchesToolRegistry() {
        var expected = BuildCatalogJson();
        var path = Path.Combine(FindWebsiteRoot(), "data", "tools-catalog.json");

        if (Environment.GetEnvironmentVariable("DD_UPDATE_TOOL_CATALOG") == "1") {
            File.WriteAllText(path, expected);
        }

        Assert.True(File.Exists(path), $"Missing {path}. Run the tests with DD_UPDATE_TOOL_CATALOG=1 to create it.");
        var actual = File.ReadAllText(path).Replace("\r\n", "\n");
        Assert.True(
            string.Equals(expected, actual, StringComparison.Ordinal),
            "Website/data/tools-catalog.json is out of date with ToolRegistry. Run the website tests with DD_UPDATE_TOOL_CATALOG=1 and commit the result.");
    }

    [Fact]
    public void EveryRegisteredToolHasAStaticRoute() {
        var registry = new ToolRegistry();
        using var document = JsonDocument.Parse(BuildCatalogJson());
        var routed = document.RootElement.GetProperty("tools").EnumerateArray()
            .Select(tool => tool.GetProperty("slug").GetString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var tool in registry.GetAll()) {
            Assert.Contains(tool.Slug, routed);
        }
    }

    internal static string BuildCatalogJson() {
        var registry = new ToolRegistry();
        var tools = registry.GetAll();

        var categories = CategoryOrder
            .Select(category => new {
                Category = category,
                Tools = tools.Where(tool => tool.Category == category).ToList()
            })
            .Where(group => group.Tools.Count > 0)
            .Select(group => new CatalogCategory(
                ToolRegistry.GetCategorySlug(group.Category),
                ToolRegistry.GetCategoryDisplayName(group.Category),
                ToolRegistry.GetCategorySummary(group.Category),
                ToolRegistry.GetCategoryIcon(group.Category),
                group.Tools.Count,
                group.Tools.Select(ToEntry).ToList()))
            .ToList();

        var flat = categories.SelectMany(category => category.Tools).ToList();
        var catalog = new Catalog(flat.Count, flat.Count(tool => tool.Support == "browser"), categories, flat);
        return JsonSerializer.Serialize(catalog, JsonOptions).Replace("\r\n", "\n") + "\n";
    }

    private static CatalogTool ToEntry(ToolDefinition tool) {
        var support = tool.BrowserCompatible ? "browser" : tool.LiteCompatible ? "partial" : "local";
        var supportLabel = support switch {
            "browser" => "Runs in your browser",
            "partial" => "Partial in browser, full locally",
            _ => "Runs locally with PowerShell or the CLI"
        };

        return new CatalogTool(
            tool.Slug,
            tool.Name,
            tool.Description,
            ToolRegistry.GetCategorySlug(tool.Category),
            ToolRegistry.GetCategoryDisplayName(tool.Category),
            support,
            supportLabel,
            tool.InputPlaceholder ?? "example.com",
            tool.CliExample ?? string.Empty,
            tool.PowerShellExample ?? string.Empty,
            tool.CSharpExample ?? string.Empty);
    }

    private static string FindWebsiteRoot() {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null) {
            var candidate = Path.Combine(directory.FullName, "Website", "site.json");
            if (File.Exists(candidate)) {
                return Path.Combine(directory.FullName, "Website");
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find Website/site.json above the test output directory.");
    }

    private sealed record Catalog(int Count, int BrowserCount, IReadOnlyList<CatalogCategory> Categories, IReadOnlyList<CatalogTool> Tools);

    private sealed record CatalogCategory(string Slug, string Name, string Summary, string Icon, int Count, IReadOnlyList<CatalogTool> Tools);

    private sealed record CatalogTool(
        string Slug,
        string Name,
        string Description,
        string Category,
        string CategoryName,
        string Support,
        string SupportLabel,
        string Placeholder,
        string Cli,
        [property: JsonPropertyName("powershell")] string PowerShell,
        [property: JsonPropertyName("csharp")] string CSharp);
}
