using System.Text.Json.Serialization;

namespace DomainDetective.Website.Models;

public sealed class SiteNavigationData {
    public List<SiteNavigationItem> Primary { get; set; } = new();
    public Dictionary<string, List<SiteNavigationItem>> Menus { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<SiteNavigationAction> Actions { get; set; } = new();
}

public sealed class SiteNavigationItem {
    public string? Href { get; set; }
    public string? Text { get; set; }
    public string? Title { get; set; }
    public bool External { get; set; }
    public string? Target { get; set; }
    public string? Rel { get; set; }
    public List<SiteNavigationItem> Items { get; set; } = new();

    [JsonIgnore]
    public string Label => string.IsNullOrWhiteSpace(Text) ? Title ?? string.Empty : Text;
}

public sealed class SiteNavigationAction {
    public string? Title { get; set; }
    public string? AriaLabel { get; set; }
    public string? Kind { get; set; }

    [JsonPropertyName("class")]
    public string? CssClass { get; set; }

    public string? IconHtml { get; set; }
    public string? Text { get; set; }
    public string? Href { get; set; }
    public bool External { get; set; }
    public string? Target { get; set; }
    public string? Rel { get; set; }
}
