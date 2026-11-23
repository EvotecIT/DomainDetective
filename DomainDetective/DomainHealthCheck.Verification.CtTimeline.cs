using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>Environment variable naming a DDCT endpoint that the CT timeline queries before crt.sh.</summary>
    public const string DdctUrlEnvironmentVariable = "DOMAINDETECTIVE_DDCT_URL";

    /// <summary>Environment variable holding the DDCT API key.</summary>
    public const string DdctApiKeyEnvironmentVariable = "DOMAINDETECTIVE_DDCT_API_KEY";

    /// <summary>Environment variable naming the DDCT scope to query.</summary>
    public const string DdctScopeEnvironmentVariable = "DOMAINDETECTIVE_DDCT_SCOPE";

    /// <summary>
    /// Builds a certificate transparency (CT) timeline for the specified domain. When
    /// <see cref="CertificateTransparencyTimelineAnalysis.Provider"/> is not set and
    /// <c>DOMAINDETECTIVE_DDCT_URL</c> is, the timeline is read from that DDCT instance first.
    /// </summary>
    public Task VerifyCtTimelineAsync(string domainName, CancellationToken cancellationToken = default) =>
        CompleteDirectCheckAsync(HealthCheckType.CTTIMELINE, () => VerifyCtTimelineAsyncDirectCore(domainName, cancellationToken), cancellationToken, ownerDomain: domainName);

    private async Task VerifyCtTimelineAsyncDirectCore(string domainName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domainName))
        {
            throw new ArgumentNullException(nameof(domainName));
        }

        domainName = NormalizeDomain(domainName);
        UpdateIsPublicSuffix(domainName);
        if (IsPublicSuffix)
        {
            return;
        }

        if (CtTimelineAnalysis.Provider == null && CreateDdctProviderFromEnvironment() is { } provider)
        {
            CtTimelineAnalysis.Provider = provider;
        }

        await CtTimelineAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken).ConfigureAwait(false);
    }

    private static DdctApiCertificateTransparencyProvider? CreateDdctProviderFromEnvironment()
    {
        string? url = Environment.GetEnvironmentVariable(DdctUrlEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        return new DdctApiCertificateTransparencyProvider(SharedHttpClient.Instance, new DdctApiCertificateTransparencyProviderOptions
        {
            EndpointUrl = url!.Trim(),
            ApiKey = Environment.GetEnvironmentVariable(DdctApiKeyEnvironmentVariable),
            ScopeName = Environment.GetEnvironmentVariable(DdctScopeEnvironmentVariable)
        });
    }
}
