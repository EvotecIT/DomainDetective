using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMicrosoftIdentityProbeClient
{
    [Fact]
    public async Task ParsesOpenIdConfigurationAndUserRealm()
    {
        var factory = new StubHttpClientFactory(request => {
            if (request.RequestUri!.AbsoluteUri.Contains(".well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)) {
                return CreateJsonResponse(@"
{
  ""issuer"": ""https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"",
  ""token_endpoint"": ""https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token"",
  ""cloud_instance_name"": ""microsoftonline.com"",
  ""tenant_region_scope"": ""EU"",
  ""grant_types_supported"": [""authorization_code""],
  ""response_types_supported"": [""code"", ""id_token""]
}");
            }

            return CreateJsonResponse(@"
{
  ""NameSpaceType"": ""Managed"",
  ""AuthURL"": ""https://login.microsoftonline.com/"",
  ""CloudInstanceName"": ""microsoftonline.com""
}");
        });

        var discovery = await MicrosoftIdentityProbeClient.TryGetOpenIdConfigurationAsync("contoso.com", factory, CancellationToken.None);
        var realm = await MicrosoftIdentityProbeClient.TryGetUserRealmAsync("contoso.com", factory, CancellationToken.None);

        Assert.NotNull(discovery);
        Assert.Equal("microsoftonline.com", discovery!.CloudInstanceName);
        Assert.Equal("EU", discovery.TenantRegionScope);
        Assert.Contains("authorization_code", discovery.GrantTypesSupported);
        Assert.Contains("code", discovery.ResponseTypesSupported);

        Assert.NotNull(realm);
        Assert.Equal("Managed", realm!.NameSpaceType);
        Assert.Equal("https://login.microsoftonline.com/", realm.AuthUrl);
    }

    [Fact]
    public async Task ParsesCredentialTypeProbe()
    {
        var factory = new StubHttpClientFactory(_ => CreateJsonResponse(@"
{
  ""Username"": ""user@contoso.com"",
  ""Display"": ""user@contoso.com"",
  ""IfExistsResult"": 1,
  ""IsUnmanaged"": false,
  ""ThrottleStatus"": 1,
  ""Credentials"": { ""PrefCredential"": 4, ""FederationRedirectUrl"": ""https://login.microsoftonline.com/"" },
  ""EstsProperties"": { ""DomainType"": 3 }
}"));

        var probe = await MicrosoftIdentityProbeClient.TryGetCredentialTypeAsync("user@contoso.com", factory, CancellationToken.None);

        Assert.NotNull(probe);
        Assert.Equal("user@contoso.com", probe!.Username);
        Assert.Equal(1, probe.IfExistsResult);
        Assert.Equal(1, probe.ThrottleStatus);
        Assert.Equal(4, probe.PreferredCredential);
        Assert.Equal(3, probe.DomainType);
        Assert.Equal("https://login.microsoftonline.com/", probe.FederationRedirectUrl);
    }

    [Fact]
    public async Task ReturnsNullForMalformedJsonResponses()
    {
        var factory = new StubHttpClientFactory(_ => CreateJsonResponse("{ not-valid-json"));

        var discovery = await MicrosoftIdentityProbeClient.TryGetOpenIdConfigurationAsync("contoso.com", factory, CancellationToken.None);
        var realm = await MicrosoftIdentityProbeClient.TryGetUserRealmAsync("contoso.com", factory, CancellationToken.None);
        var probe = await MicrosoftIdentityProbeClient.TryGetCredentialTypeAsync("user@contoso.com", factory, CancellationToken.None);

        Assert.Null(discovery);
        Assert.Null(realm);
        Assert.Null(probe);
    }

    private static HttpResponseMessage CreateJsonResponse(string json)
    {
        return new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }
}

internal sealed class StubHttpClientFactory : IHttpClientFactory
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public StubHttpClientFactory(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
    }

    public HttpClient CreateClient()
    {
        return new HttpClient(new StubHttpMessageHandler(_responder), disposeHandler: true);
    }
}

internal sealed class StubHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(_responder(request));
    }
}
