namespace DomainDetective.Toolbox.Models;

public sealed class ToolDefinition {
    public required string Name { get; init; }
    public required string Slug { get; init; }
    public required string Description { get; init; }
    public required ToolCategory Category { get; init; }
    public required string Icon { get; init; }
    public bool BrowserCompatible { get; init; } = true;
    public bool HostedCompatible { get; init; }
    public bool LiteCompatible { get; init; }
    public string? InputPlaceholder { get; init; }
    public string? SecondaryInputLabel { get; init; }
    public string? SecondaryInputPlaceholder { get; init; }
}
