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
    /// <summary>Gets or sets the http client factory value.</summary>
    public IHttpClientFactory? HttpClientFactory { get; set; }
    /// <summary>Gets or sets the domain value.</summary>
    public string? Domain { get; private set; }
    /// <summary>Gets or sets the discovery url value.</summary>
    public string? DiscoveryUrl { get; private set; }
    /// <summary>Gets or sets the tenant id value.</summary>
    public string? TenantId { get; private set; }
    /// <summary>Gets or sets the name space type value.</summary>
    public string? NameSpaceType { get; private set; }
    /// <summary>Gets or sets the federated auth url value.</summary>
    public string? FederatedAuthUrl { get; private set; }
    /// <summary>Gets or sets the identity provider host value.</summary>
    public string? IdentityProviderHost { get; private set; }
    /// <summary>Gets or sets the domain name value.</summary>
    public string? DomainName { get; private set; }
    /// <summary>Gets or sets the federation brand name value.</summary>
    public string? FederationBrandName { get; private set; }
    /// <summary>Gets or sets the cloud instance name value.</summary>
    public string? CloudInstanceName { get; private set; }
    /// <summary>Gets or sets the tenant region scope value.</summary>
    public string? TenantRegionScope { get; private set; }
    /// <summary>Gets or sets the tenant region sub scope value.</summary>
    public string? TenantRegionSubScope { get; private set; }
    /// <summary>Gets or sets the grant types supported value.</summary>
    public IReadOnlyList<string> GrantTypesSupported { get; private set; } = Array.Empty<string>();
    /// <summary>Gets or sets the response types supported value.</summary>
    public IReadOnlyList<string> ResponseTypesSupported { get; private set; } = Array.Empty<string>();
    /// <summary>Gets or sets the discovery succeeded value.</summary>
    public bool DiscoverySucceeded { get; private set; }
    /// <summary>Gets or sets the get user realm succeeded value.</summary>
    public bool GetUserRealmSucceeded { get; private set; }

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Analyzes async.</summary>
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
