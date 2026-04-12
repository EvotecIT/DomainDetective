using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Defines a reusable certificate transparency provider for certificate and domain discovery work.
/// </summary>
public interface ICtCertificateTransparencyProvider
{
    /// <summary>Stable provider identifier.</summary>
    string ProviderId { get; }

    /// <summary>Provider profile describing capabilities and safe default limits.</summary>
    CtProviderProfile Profile { get; }

    /// <summary>
    /// Executes a normalized CT query.
    /// </summary>
    /// <param name="query">Query requested by the caller.</param>
    /// <param name="runtimeState">Optional persisted provider runtime state.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<CtCertificateQueryResult> QueryAsync(
        CtCertificateQuery query,
        CtProviderRuntimeState? runtimeState = null,
        CancellationToken cancellationToken = default);
}
