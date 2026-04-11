using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Helper methods for paged certificate transparency providers.
/// </summary>
public static class CtCertificateTransparencyProviderExtensions
{
    /// <summary>
    /// Queries a CT provider page-by-page until no continuation token is returned or the optional page limit is reached.
    /// </summary>
    /// <param name="provider">Provider to query.</param>
    /// <param name="query">Initial query.</param>
    /// <param name="runtimeState">Optional persisted provider runtime state.</param>
    /// <param name="maxPages">Optional safety cap for provider pages. Null means no explicit cap.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async IAsyncEnumerable<CtCertificateQueryResult> QueryPagesAsync(
        this ICtCertificateTransparencyProvider provider,
        CtCertificateQuery query,
        CtProviderRuntimeState? runtimeState = null,
        int? maxPages = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (provider == null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        if (query == null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        int remainingPages = maxPages.HasValue && maxPages.Value > 0
            ? maxPages.Value
            : int.MaxValue;
        string? previousContinuationToken = null;
        CtCertificateQuery currentQuery = query.Normalize();
        while (remainingPages > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CtCertificateQueryResult result = await provider
                .QueryAsync(currentQuery, runtimeState, cancellationToken)
                .ConfigureAwait(false);

            yield return result;
            remainingPages--;

            string? continuationToken = string.IsNullOrWhiteSpace(result.ContinuationToken)
                ? null
                : result.ContinuationToken!.Trim();
            if (!result.HasMore ||
                continuationToken == null ||
                string.Equals(continuationToken, previousContinuationToken, StringComparison.Ordinal))
            {
                yield break;
            }

            previousContinuationToken = continuationToken;
            runtimeState = result.ProviderState ?? runtimeState;
            currentQuery = currentQuery.WithContinuationToken(continuationToken);
        }
    }

    private static CtCertificateQuery WithContinuationToken(this CtCertificateQuery query, string continuationToken)
    {
        return new CtCertificateQuery
        {
            Name = query.Name,
            QueryKind = query.QueryKind,
            Operations = query.Operations,
            RequireFullCertificate = query.RequireFullCertificate,
            ContinuationToken = continuationToken,
            PageSize = query.PageSize,
            Timeout = query.Timeout
        };
    }
}
