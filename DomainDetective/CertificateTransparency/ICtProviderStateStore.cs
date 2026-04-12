using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Persists certificate transparency provider runtime state for resumable services.
/// </summary>
public interface ICtProviderStateStore
{
    /// <summary>
    /// Gets the runtime state for the requested provider.
    /// </summary>
    /// <param name="providerId">Stable provider identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<CtProviderRuntimeState?> GetAsync(string providerId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Saves the runtime state for a provider.
    /// </summary>
    /// <param name="state">Provider runtime state to persist.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task SaveAsync(CtProviderRuntimeState state, CancellationToken cancellationToken = default);
}
