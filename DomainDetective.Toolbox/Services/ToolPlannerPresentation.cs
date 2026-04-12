using DomainDetective.Toolbox.Models;

namespace DomainDetective.Toolbox.Services;

public enum ToolPlannerMode {
    AvailableNow,
    Adaptive,
    GuidedLocally,
    Online
}

public static class ToolPlannerPresentation {
    public static string? NormalizeDomain(string? domain) {
        return string.IsNullOrWhiteSpace(domain) ? null : domain.Trim();
    }

    public static bool IsOverviewTool(ToolDefinition tool) {
        ArgumentNullException.ThrowIfNull(tool);

        return tool.Category == ToolCategory.Overview;
    }

    public static string BuildCatalogUrl(string? domain) {
        var normalizedDomain = NormalizeDomain(domain);
        return normalizedDomain is null
            ? "/tools/"
            : $"/tools/?q={Uri.EscapeDataString(normalizedDomain)}";
    }

    public static string BuildToolUrl(ToolDefinition tool, string? domain) {
        ArgumentNullException.ThrowIfNull(tool);

        var baseUrl = $"/tools/{tool.Slug}/";
        var normalizedDomain = NormalizeDomain(domain);
        return normalizedDomain is null
            ? baseUrl
            : $"{baseUrl}?q={Uri.EscapeDataString(normalizedDomain)}";
    }

    public static ToolPlannerMode GetMode(ToolDefinition tool, ToolsDeploymentMode deploymentMode) {
        ArgumentNullException.ThrowIfNull(tool);

        if (deploymentMode != ToolsDeploymentMode.StaticOnly) {
            return ToolPlannerMode.Online;
        }

        if (tool.HostedCompatible && !tool.BrowserCompatible && tool.LiteCompatible) {
            return ToolPlannerMode.Adaptive;
        }

        if (tool.HostedCompatible && !tool.BrowserCompatible) {
            return ToolPlannerMode.GuidedLocally;
        }

        return ToolPlannerMode.AvailableNow;
    }

    public static string GetModeLabel(ToolDefinition tool, ToolsDeploymentMode deploymentMode) {
        return GetMode(tool, deploymentMode) switch {
            ToolPlannerMode.Adaptive => "Partial browser",
            ToolPlannerMode.GuidedLocally => "Guided locally",
            ToolPlannerMode.Online => "Online",
            _ => "Runs in browser"
        };
    }

    public static int CountToolsByMode(IEnumerable<ToolDefinition> tools, ToolsDeploymentMode deploymentMode, ToolPlannerMode mode) {
        ArgumentNullException.ThrowIfNull(tools);

        return tools.Count(tool => GetMode(tool, deploymentMode) == mode);
    }
}
