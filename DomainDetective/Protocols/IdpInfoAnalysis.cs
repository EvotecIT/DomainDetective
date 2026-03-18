using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Detects identity tenant details using OIDC discovery and GetUserRealm.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class IdpInfoAnalysis : IHasAssessments
{
    public IHttpClientFactory? HttpClientFactory { get; set; }
    public string? Domain { get; private set; }
    public string? DiscoveryUrl { get; private set; }
    public string? TenantId { get; private set; }
    public string? NameSpaceType { get; private set; }
    public string? FederatedAuthUrl { get; private set; }
    public string? IdentityProviderHost { get; private set; }
    public string? DomainName { get; private set; }
    public string? FederationBrandName { get; private set; }
    public string? CloudInstanceName { get; private set; }
    public string? TenantRegionScope { get; private set; }
    public string? TenantRegionSubScope { get; private set; }
    public IReadOnlyList<string> GrantTypesSupported { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> ResponseTypesSupported { get; private set; } = Array.Empty<string>();
    public bool DiscoverySucceeded { get; private set; }
    public bool GetUserRealmSucceeded { get; private set; }

    public List<Assessment> Assessments { get; } = new();

    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken ct = default)
    {
        Domain = domain;
        DiscoveryUrl = null;
        TenantId = null;
        NameSpaceType = null;
        FederatedAuthUrl = null;
        IdentityProviderHost = null;
        DomainName = null;
        FederationBrandName = null;
        CloudInstanceName = null;
        TenantRegionScope = null;
        TenantRegionSubScope = null;
        GrantTypesSupported = Array.Empty<string>();
        ResponseTypesSupported = Array.Empty<string>();
        DiscoverySucceeded = false;
        GetUserRealmSucceeded = false;
        var discovery = await MicrosoftIdentityProbeClient.TryGetOpenIdConfigurationAsync(domain, HttpClientFactory, ct).ConfigureAwait(false);
        if (discovery != null)
        {
            DiscoveryUrl = discovery.DiscoveryUrl;
            DiscoverySucceeded = true;
            IdentityProviderHost = TryGetHost(discovery.Issuer) ?? TryGetHost(discovery.TokenEndpoint);
            CloudInstanceName = discovery.CloudInstanceName;
            TenantRegionScope = discovery.TenantRegionScope;
            TenantRegionSubScope = discovery.TenantRegionSubScope;
            GrantTypesSupported = discovery.GrantTypesSupported;
            ResponseTypesSupported = discovery.ResponseTypesSupported;
            TenantId = TryExtractTenantId(discovery.TokenEndpoint);
        }

        var realm = await MicrosoftIdentityProbeClient.TryGetUserRealmAsync(domain, HttpClientFactory, ct).ConfigureAwait(false);
        if (realm != null)
        {
            NameSpaceType = realm.NameSpaceType;
            DomainName = realm.DomainName;
            FederationBrandName = realm.FederationBrandName;
            FederatedAuthUrl = realm.AuthUrl;
            if (string.IsNullOrWhiteSpace(IdentityProviderHost))
            {
                IdentityProviderHost = TryGetHost(FederatedAuthUrl) ?? "login.microsoftonline.com";
            }
            if (string.IsNullOrWhiteSpace(CloudInstanceName))
            {
                CloudInstanceName = realm.CloudInstanceName;
            }
            GetUserRealmSucceeded = true;
        }
    }

    private static string? TryGetHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            return absolute.Host;
        }

        return null;
    }

    private static string? TryExtractTenantId(string? tokenEndpoint)
    {
        if (!Uri.TryCreate(tokenEndpoint, UriKind.Absolute, out var absolute))
        {
            return null;
        }

        var parts = absolute.AbsolutePath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (Guid.TryParse(part, out var _))
            {
                return part;
            }
        }

        return null;
    }
}
