using DomainDetective.Toolbox.Models;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Json;
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace DomainDetective.Toolbox.Services;

public sealed class ToolAvailabilityService {
    private static readonly TimeSpan DetectionTimeout = TimeSpan.FromSeconds(2);
    private const string RuntimeConfigPath = "data/tools-runtime.json";
    private readonly ToolsDeploymentMode? _configuredMode;
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _initializationLock = new(1, 1);
    private volatile bool _isInitialized;

    public ToolAvailabilityService(IConfiguration configuration, HttpClient httpClient) {
        _httpClient = httpClient;
        var configuredMode = configuration["Tools:Mode"];
        if (!string.IsNullOrWhiteSpace(configuredMode) &&
            !string.Equals(configuredMode, "Auto", StringComparison.OrdinalIgnoreCase) &&
            Enum.TryParse(configuredMode, ignoreCase: true, out ToolsDeploymentMode parsedMode)) {
            _configuredMode = parsedMode;
            Mode = parsedMode;
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
            _ => definition.BrowserCompatible || definition.LiteCompatible
        };
    }

    public bool CanRun(ToolDefinition definition) {
        // In the current product model, visible tools are also runnable.
        return CanList(definition);
    }

    public IReadOnlyList<ToolDefinition> FilterVisible(IEnumerable<ToolDefinition> tools) {
        if (tools == null) {
            throw new ArgumentNullException(nameof(tools));
        }

        return tools.Where(CanList).ToArray();
    }

    public string GetHomeDescription() {
        return Mode switch {
            ToolsDeploymentMode.HostedOnline => "Comprehensive domain security analysis across DNS, mail, web, registration, and exposure posture.",
            _ => "Web-ready domain security analysis with live DNS, mail, adaptive overview checks, and local workflows for deeper tools."
        };
    }

    public string GetUnavailableMessage(ToolDefinition definition) {
        if (definition == null) {
            throw new ArgumentNullException(nameof(definition));
        }

        return definition.LiteCompatible
            ? $"{definition.Name} is available here as a lighter web edition."
            : $"{definition.Name} is not available in this web edition yet.";
    }

    private async Task<ToolsDeploymentMode> DetectModeAsync(CancellationToken cancellationToken) {
        var configuredRuntimeMode = await TryReadRuntimeModeAsync(cancellationToken).ConfigureAwait(false);
        if (configuredRuntimeMode.HasValue) {
            return configuredRuntimeMode.Value;
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var detectionCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        detectionCancellationTokenSource.CancelAfter(DetectionTimeout);

        try {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/tool-api/health");
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, detectionCancellationTokenSource.Token).ConfigureAwait(false);

            return response.IsSuccessStatusCode ? ToolsDeploymentMode.HostedOnline : ToolsDeploymentMode.StaticOnly;
        } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
            return ToolsDeploymentMode.StaticOnly;
        } catch (HttpRequestException) {
            return ToolsDeploymentMode.StaticOnly;
        } catch (InvalidOperationException) {
            return ToolsDeploymentMode.StaticOnly;
        }
    }

    private async Task<ToolsDeploymentMode?> TryReadRuntimeModeAsync(CancellationToken cancellationToken) {
        try {
            var runtimeConfiguration = await _httpClient
                .GetFromJsonAsync<ToolRuntimeConfiguration>(RuntimeConfigPath, cancellationToken)
                .ConfigureAwait(false);

            if (runtimeConfiguration == null || string.IsNullOrWhiteSpace(runtimeConfiguration.Mode)) {
                return null;
            }

            return Enum.TryParse(runtimeConfiguration.Mode, ignoreCase: true, out ToolsDeploymentMode parsedMode)
                ? parsedMode
                : null;
        } catch (HttpRequestException) {
            return null;
        } catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested) {
            return null;
        } catch (InvalidOperationException) {
            return null;
        } catch (JsonException) {
            return null;
        } catch (NotSupportedException) {
            return null;
        }
    }

    private sealed class ToolRuntimeConfiguration {
        public string? Mode { get; set; }
    }
}
