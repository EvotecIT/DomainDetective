namespace DomainDetective.Toolbox.Models;

public sealed class ToolResult {
    public required string ToolName { get; init; }
    public required string Domain { get; init; }
    public bool IsSuccess { get; init; }
    public bool IsLoading { get; set; }
    public string? ErrorMessage { get; set; }
    public object? Data { get; set; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}
