using DomainDetective.Toolbox.Models;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace DomainDetective.Toolbox.Services;

public sealed class ToolAvailabilityService {
    private readonly HttpClient _httpClient;
    private readonly ToolsDeploymentMode? _configuredMode;
    private readonly SemaphoreSlim _initializationLock = new(1, 1);
    private bool _isInitialized;

    public ToolAvailabilityService(HttpClient httpClient, IConfiguration configuration) {
        _httpClient = httpClient;

        var configuredMode = configuration["Tools:Mode"];
        if (Enum.TryParse(configuredMode, ignoreCase: true, out ToolsDeploymentMode parsedMode)) {
            _configuredMode = parsedMode;
            Mode = parsedMode;
            _isInitialized = true;
            return;
        }

        Mode = ToolsDeploymentMode.StaticOnly;
    }

    public ToolsDeploymentMode Mode { get; private set; }

    public bool IsStaticOnly => Mode == ToolsDeploymentMode.StaticOnly;

    public bool IsHostedOnline => Mode == ToolsDeploymentMode.HostedOnline;

    public async Task InitializeAsync(CancellationToken cancellationToken = default) {
        if (_isInitialized) {
            return;
        }

        await _initializationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try {
            if (_isInitialized) {
                return;
            }

            if (_configuredMode.HasValue) {
                Mode = _configuredMode.Value;
                _isInitialized = true;
                return;
            }

            Mode = await DetectModeAsync(cancellationToken).ConfigureAwait(false);
            _isInitialized = true;
        } finally {
            _initializationLock.Release();
        }
    }

    public bool CanList(ToolDefinition definition) {
        if (definition == null) {
            throw new ArgumentNullException(nameof(definition));
        }

        return Mode switch {
            ToolsDeploymentMode.HostedOnline => definition.BrowserCompatible || definition.HostedCompatible,
            _ => definition.BrowserCompatible || SupportsLiteExperience(definition)
        };
    }

    public bool CanRun(ToolDefinition definition) {
        return CanList(definition);
    }

    public IReadOnlyList<ToolDefinition> FilterVisible(IEnumerable<ToolDefinition> tools) {
        if (tools == null) {
            throw new ArgumentNullException(nameof(tools));
        }

        return tools.Where(CanList).ToList();
    }

    public string GetHomeDescription() {
        return Mode switch {
            ToolsDeploymentMode.HostedOnline => "Comprehensive domain security analysis across DNS, mail, web, registration, and exposure posture.",
            _ => "Web-ready domain security analysis with live DNS, mail, and browser-safe overview checks."
        };
    }

    public string GetUnavailableMessage(ToolDefinition definition) {
        if (definition == null) {
            throw new ArgumentNullException(nameof(definition));
        }

        if (definition.BrowserCompatible) {
            return $"{definition.Name} is available in this deployment.";
        }

        return $"{definition.Name} is not available in this web edition yet.";
    }

    private async Task<ToolsDeploymentMode> DetectModeAsync(CancellationToken cancellationToken) {
        try {
            using var response = await _httpClient.GetAsync("/tool-api/health", cancellationToken).ConfigureAwait(false);
            return response.StatusCode == HttpStatusCode.OK
                ? ToolsDeploymentMode.HostedOnline
                : ToolsDeploymentMode.StaticOnly;
        } catch {
            return ToolsDeploymentMode.StaticOnly;
        }
    }

    private static bool SupportsLiteExperience(ToolDefinition definition) {
        return definition.Slug == "m365-overview" ||
               definition.Slug == "domain-overview" ||
               definition.Slug == "mta-sts" ||
               definition.Slug == "dns-propagation";
    }
}
