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
    public string? Domain { get; private set; }
    public string? DiscoveryUrl { get; private set; }
    public string? TenantId { get; private set; }
    public string? NameSpaceType { get; private set; }
    public string? FederatedAuthUrl { get; private set; }
    public bool DiscoverySucceeded { get; private set; }
    public bool GetUserRealmSucceeded { get; private set; }

    public List<Assessment> Assessments { get; } = new();

    public async Task AnalyzeAsync(string domain, InternalLogger? logger = null, CancellationToken ct = default)
    {
        Domain = domain;
        DiscoverySucceeded = false; GetUserRealmSucceeded = false;
        // Try login.windows.net first, then microsoftonline.com
        var candidates = new[] {
            $"https://login.windows.net/{domain}/.well-known/openid-configuration",
            $"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        };

        foreach (var url in candidates)
        {
            try
            {
                using var resp = await SharedHttpClient.Instance.GetAsync(url, ct).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) continue;
                System.IO.Stream stream;
#if NET6_0_OR_GREATER
                stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
                stream = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
                var root = doc.RootElement;
                var tokenEndpoint = root.TryGetProperty("token_endpoint", out var te) ? te.GetString() : null;
                if (!string.IsNullOrWhiteSpace(tokenEndpoint))
                {
                    DiscoveryUrl = url;
                    DiscoverySucceeded = true;
                    // Extract tenant GUID if present in token_endpoint (.../oauth2/token or v2.0 token)
                    // We will capture the path element that looks like a GUID
                    try
                    {
                        var parts = new Uri(tokenEndpoint!).AbsolutePath.Split(new [] {'/'}, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var p in parts)
                        {
                            if (Guid.TryParse(p, out var _)) { TenantId = p; break; }
                        }
                    } catch { }
                    break;
                }
            }
            catch (HttpRequestException)
            {
                continue;
            }
        }

        // GetUserRealm for namespace type and federated URL
        try
        {
            var url = $"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&json=1";
            using var resp = await SharedHttpClient.Instance.GetAsync(url, ct).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
            {
                System.IO.Stream stream2;
#if NET6_0_OR_GREATER
                stream2 = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
                stream2 = await resp.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
                using var doc = await JsonDocument.ParseAsync(stream2, cancellationToken: ct).ConfigureAwait(false);
                var root = doc.RootElement;
                NameSpaceType = root.TryGetProperty("NameSpaceType", out var ns) ? ns.GetString() : null;
                FederatedAuthUrl = root.TryGetProperty("AuthURL", out var au) ? au.GetString() : null;
                GetUserRealmSucceeded = true;
            }
        }
        catch (HttpRequestException) { }
    }
}
