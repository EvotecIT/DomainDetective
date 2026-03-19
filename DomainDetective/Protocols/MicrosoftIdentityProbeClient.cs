using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Shared public Microsoft identity probe helpers used by domain and mailbox analyses.
/// </summary>
public static class MicrosoftIdentityProbeClient {
    private const string GetCredentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType";
    private static readonly SharedHttpClient FallbackHttpClientFactory = new();

    /// <summary>
    /// Tries Microsoft OIDC discovery for a domain using known public endpoints.
    /// </summary>
    public static async Task<MicrosoftOpenIdConfigurationProbe?> TryGetOpenIdConfigurationAsync(
        string domain,
        IHttpClientFactory? httpClientFactory = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        var client = CreateClient(httpClientFactory);
        var candidates = new[] {
            $"https://login.windows.net/{domain}/.well-known/openid-configuration",
            $"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        };

        for (var i = 0; i < candidates.Length; i++) {
            var url = candidates[i];
            try {
                using var response = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    continue;
                }

                using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                var root = doc.RootElement;
                var tokenEndpoint = root.TryGetProperty("token_endpoint", out var te) ? te.GetString() : null;
                if (string.IsNullOrWhiteSpace(tokenEndpoint)) {
                    continue;
                }

                return new MicrosoftOpenIdConfigurationProbe {
                    DiscoveryUrl = url,
                    Issuer = root.TryGetProperty("issuer", out var issuer) ? issuer.GetString() : null,
                    TokenEndpoint = tokenEndpoint!,
                    CloudInstanceName = root.TryGetProperty("cloud_instance_name", out var cloud) ? cloud.GetString() : null,
                    TenantRegionScope = root.TryGetProperty("tenant_region_scope", out var region) ? region.GetString() : null,
                    TenantRegionSubScope = root.TryGetProperty("tenant_region_sub_scope", out var subRegion) ? subRegion.GetString() : null,
                    GrantTypesSupported = ReadStringArray(root, "grant_types_supported"),
                    ResponseTypesSupported = ReadStringArray(root, "response_types_supported")
                };
            } catch (Exception ex) when (ShouldTreatAsNullProbeResult(ex, cancellationToken)) {
                continue;
            }
        }

        return null;
    }

    /// <summary>
    /// Queries Microsoft GetUserRealm for namespace/federation hints.
    /// </summary>
    public static async Task<MicrosoftUserRealmProbe?> TryGetUserRealmAsync(
        string domain,
        IHttpClientFactory? httpClientFactory = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
        }

        var client = CreateClient(httpClientFactory);
        var url = "https://login.microsoftonline.com/getuserrealm.srf?login=" +
                  Uri.EscapeDataString("user@" + domain) +
                  "&json=1";

        try {
            using var response = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return null;
            }

            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var root = doc.RootElement;
            return new MicrosoftUserRealmProbe {
                QueryUrl = url,
                NameSpaceType = root.TryGetProperty("NameSpaceType", out var ns) ? ns.GetString() : null,
                DomainName = root.TryGetProperty("DomainName", out var domainName) ? domainName.GetString() : null,
                FederationBrandName = root.TryGetProperty("FederationBrandName", out var federationBrandName) ? federationBrandName.GetString() : null,
                AuthUrl = root.TryGetProperty("AuthURL", out var auth) ? auth.GetString() : null,
                CloudInstanceName = root.TryGetProperty("CloudInstanceName", out var cloud) ? cloud.GetString() : null
            };
        } catch (Exception ex) when (ShouldTreatAsNullProbeResult(ex, cancellationToken)) {
            return null;
        }
    }

    /// <summary>
    /// Queries the public GetCredentialType endpoint for a username hint.
    /// </summary>
    public static async Task<MicrosoftCredentialTypeProbe?> TryGetCredentialTypeAsync(
        string username,
        IHttpClientFactory? httpClientFactory = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(username)) {
            throw new ArgumentNullException(nameof(username));
        }

        var payload = new Dictionary<string, object> {
            { "Username", username },
            { "isOtherIdpSupported", true },
            { "checkPhones", false },
            { "isRemoteNGCSupported", true },
            { "isCookieBannerShown", false },
            { "isFidoSupported", true },
            { "forceotclogin", false },
            { "isExternalFederationDisallowed", false },
            { "isRemoteConnectSupported", false },
            { "federationFlags", 0 },
            { "isSignup", false },
            { "flowToken", string.Empty },
            { "isAccessPassSupported", true }
        };

        var client = CreateClient(httpClientFactory);
        using var request = new HttpRequestMessage(HttpMethod.Post, GetCredentialTypeUrl) {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        // Microsoft returns the most consistent public tenant-routing response here when the request
        // looks like a normal browser sign-in flow rather than an API-only client.
        request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

        try {
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return null;
            }

            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var root = doc.RootElement;
            var credentials = root.TryGetProperty("Credentials", out var creds) ? creds : default;
            var estsProperties = root.TryGetProperty("EstsProperties", out var ests) ? ests : default;

            return new MicrosoftCredentialTypeProbe {
                Username = root.TryGetProperty("Username", out var actualUsername) ? actualUsername.GetString() ?? username : username,
                Display = root.TryGetProperty("Display", out var display) ? display.GetString() : null,
                IfExistsResult = root.TryGetProperty("IfExistsResult", out var exists) && exists.TryGetInt32(out var ifExistsResult) ? ifExistsResult : null,
                IsUnmanaged = root.TryGetProperty("IsUnmanaged", out var unmanaged) && unmanaged.ValueKind is JsonValueKind.True or JsonValueKind.False ? unmanaged.GetBoolean() : null,
                ThrottleStatus = root.TryGetProperty("ThrottleStatus", out var throttle) && throttle.TryGetInt32(out var throttleStatus) ? throttleStatus : null,
                PreferredCredential = credentials.ValueKind == JsonValueKind.Object && credentials.TryGetProperty("PrefCredential", out var pref) && pref.TryGetInt32(out var prefCredential) ? prefCredential : null,
                FederationRedirectUrl = credentials.ValueKind == JsonValueKind.Object && credentials.TryGetProperty("FederationRedirectUrl", out var redirect) ? redirect.GetString() : null,
                DomainType = estsProperties.ValueKind == JsonValueKind.Object && estsProperties.TryGetProperty("DomainType", out var domainType) && domainType.TryGetInt32(out var domainTypeCode) ? domainTypeCode : null
            };
        } catch (Exception ex) when (ShouldTreatAsNullProbeResult(ex, cancellationToken)) {
            return null;
        }
    }

    private static HttpClient CreateClient(IHttpClientFactory? httpClientFactory) {
        return (httpClientFactory ?? FallbackHttpClientFactory).CreateClient();
    }

    private static bool ShouldTreatAsNullProbeResult(Exception exception, CancellationToken cancellationToken) {
        if (exception is JsonException || exception is HttpRequestException) {
            return true;
        }

        return exception is TaskCanceledException && !cancellationToken.IsCancellationRequested;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement root, string propertyName) {
        if (!root.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.Array) {
            return Array.Empty<string>();
        }

        return property
            .EnumerateArray()
            .Select(static item => item.GetString())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value!)
            .ToList();
    }
}

/// <summary>
/// Parsed OIDC discovery response for Microsoft identity platform.
/// </summary>
public sealed class MicrosoftOpenIdConfigurationProbe {
    public string DiscoveryUrl { get; init; } = string.Empty;
    public string? Issuer { get; init; }
    public string TokenEndpoint { get; init; } = string.Empty;
    public string? CloudInstanceName { get; init; }
    public string? TenantRegionScope { get; init; }
    public string? TenantRegionSubScope { get; init; }
    public IReadOnlyList<string> GrantTypesSupported { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ResponseTypesSupported { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Parsed GetUserRealm response for a domain.
/// </summary>
public sealed class MicrosoftUserRealmProbe {
    public string QueryUrl { get; init; } = string.Empty;
    public string? NameSpaceType { get; init; }
    public string? DomainName { get; init; }
    public string? FederationBrandName { get; init; }
    public string? AuthUrl { get; init; }
    public string? CloudInstanceName { get; init; }
}

/// <summary>
/// Parsed GetCredentialType response for a username probe.
/// </summary>
public sealed class MicrosoftCredentialTypeProbe {
    public string Username { get; init; } = string.Empty;
    public string? Display { get; init; }
    public int? IfExistsResult { get; init; }
    public bool? IsUnmanaged { get; init; }
    public int? ThrottleStatus { get; init; }
    public int? PreferredCredential { get; init; }
    public string? FederationRedirectUrl { get; init; }
    public int? DomainType { get; init; }
}
