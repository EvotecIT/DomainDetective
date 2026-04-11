using System;

namespace DomainDetective;

/// <summary>
/// Describes a CT certificate query requested by a caller or service.
/// </summary>
public sealed class CtCertificateQuery
{
    /// <summary>Domain or host name to query.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Operations requested from the provider.</summary>
    public CtIngestionOperation Operations { get; init; } = CtIngestionOperation.GetLatestCertificate;

    /// <summary>Whether returned certificate rows must include full DER or PEM material.</summary>
    public bool RequireFullCertificate { get; init; } = true;

    /// <summary>Optional provider continuation token or cursor.</summary>
    public string? ContinuationToken { get; init; }

    /// <summary>Maximum records to return in one provider call or page.</summary>
    public int? PageSize { get; init; }

    /// <summary>Maximum wall-clock time to spend on this query.</summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>
    /// Returns a normalized copy of the query suitable for provider execution.
    /// </summary>
    public CtCertificateQuery Normalize()
    {
        string? continuationToken = ContinuationToken;
        string? normalizedContinuationToken = continuationToken == null
            ? null
            : continuationToken.Trim();
        if (normalizedContinuationToken != null &&
            normalizedContinuationToken.Length == 0)
        {
            normalizedContinuationToken = null;
        }

        return new CtCertificateQuery
        {
            Name = (Name ?? string.Empty).Trim(),
            Operations = Operations == CtIngestionOperation.None
                ? CtIngestionOperation.GetLatestCertificate
                : Operations,
            RequireFullCertificate = RequireFullCertificate,
            ContinuationToken = normalizedContinuationToken,
            PageSize = PageSize.HasValue && PageSize.Value > 0
                ? PageSize.Value
                : null,
            Timeout = Timeout.HasValue && Timeout.Value > TimeSpan.Zero
                ? Timeout.Value
                : null
        };
    }
}
