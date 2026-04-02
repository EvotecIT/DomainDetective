namespace DomainDetective.Toolbox.Models;

public sealed class ToolDefinition {
    public required string Name { get; init; }
    public required string Slug { get; init; }
    public required string Description { get; init; }
    public required ToolCategory Category { get; init; }
    public required string Icon { get; init; }
    /// <summary>
    /// Indicates that the tool can run fully in the browser-only web edition.
    /// </summary>
    public bool BrowserCompatible { get; init; } = true;
    /// <summary>
    /// Indicates that the tool can run through the hosted analysis API.
    /// </summary>
    public bool HostedCompatible { get; init; }
    /// <summary>
    /// Indicates that the tool can offer a lighter web-edition experience when the full hosted path is unavailable.
    /// </summary>
    public bool LiteCompatible { get; init; }
    public string? InputPlaceholder { get; init; }
    public string? SecondaryInputLabel { get; init; }
    public string? SecondaryInputPlaceholder { get; init; }
}
