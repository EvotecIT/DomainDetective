using System;

namespace DomainDetective;

/// <summary>
/// Describes a CT certificate query requested by a caller or service.
/// </summary>
public sealed class CtCertificateQuery
{
    /// <summary>Domain or host name to query.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Service-level intent of the query.</summary>
    public CtCertificateQueryKind QueryKind { get; init; }

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
    /// Creates a query for the latest known certificate for one exact host.
    /// </summary>
    /// <param name="hostName">Exact host name to query.</param>
    /// <param name="requireFullCertificate">Whether full certificate material is required.</param>
    public static CtCertificateQuery ForExactHostLatest(string hostName, bool requireFullCertificate = true)
    {
        return new CtCertificateQuery
        {
            Name = hostName ?? string.Empty,
            QueryKind = CtCertificateQueryKind.ExactHostLatest,
            Operations = CtIngestionOperation.GetLatestCertificate,
            RequireFullCertificate = requireFullCertificate
        };
    }

    /// <summary>
    /// Creates a query for historical certificates for one exact host.
    /// </summary>
    /// <param name="hostName">Exact host name to query.</param>
    /// <param name="requireFullCertificate">Whether full certificate material is required.</param>
    public static CtCertificateQuery ForExactHostHistory(string hostName, bool requireFullCertificate = true)
    {
        return new CtCertificateQuery
        {
            Name = hostName ?? string.Empty,
            QueryKind = CtCertificateQueryKind.ExactHostHistory,
            Operations = CtIngestionOperation.GetCertificateHistory,
            RequireFullCertificate = requireFullCertificate
        };
    }

    /// <summary>
    /// Creates a query that expands a domain into CT-observed subdomains.
    /// </summary>
    /// <param name="domainName">Registered or monitored domain to expand.</param>
    /// <param name="requireFullCertificate">Whether full certificate material is required during expansion.</param>
    public static CtCertificateQuery ForDomainExpansion(string domainName, bool requireFullCertificate = false)
    {
        return new CtCertificateQuery
        {
            Name = domainName ?? string.Empty,
            QueryKind = CtCertificateQueryKind.DomainExpansion,
            Operations = CtIngestionOperation.DiscoverSubdomains,
            RequireFullCertificate = requireFullCertificate
        };
    }

    /// <summary>
    /// Creates a query for certificates across a domain tree.
    /// </summary>
    /// <param name="domainName">Registered or monitored domain to query.</param>
    /// <param name="requireFullCertificate">Whether full certificate material is required.</param>
    public static CtCertificateQuery ForDomainTreeCertificates(string domainName, bool requireFullCertificate = true)
    {
        return new CtCertificateQuery
        {
            Name = domainName ?? string.Empty,
            QueryKind = CtCertificateQueryKind.DomainTreeCertificates,
            Operations = CtIngestionOperation.GetDomainTreeCertificates,
            RequireFullCertificate = requireFullCertificate
        };
    }

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

        CtIngestionOperation operations = Operations == CtIngestionOperation.None
            ? ResolveOperations(QueryKind)
            : Operations;
        CtCertificateQueryKind queryKind = QueryKind == CtCertificateQueryKind.Unspecified ||
                                           !QueryKindMatchesOperations(QueryKind, operations)
            ? ResolveQueryKind(operations)
            : QueryKind;

        return new CtCertificateQuery
        {
            Name = (Name ?? string.Empty).Trim(),
            QueryKind = queryKind,
            Operations = operations == CtIngestionOperation.None
                ? CtIngestionOperation.GetLatestCertificate
                : operations,
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

    private static CtIngestionOperation ResolveOperations(CtCertificateQueryKind queryKind)
    {
        return queryKind switch
        {
            CtCertificateQueryKind.DomainExpansion => CtIngestionOperation.DiscoverSubdomains,
            CtCertificateQueryKind.ExactHostHistory => CtIngestionOperation.GetCertificateHistory,
            CtCertificateQueryKind.DomainTreeCertificates => CtIngestionOperation.GetDomainTreeCertificates,
            _ => CtIngestionOperation.GetLatestCertificate
        };
    }

    private static CtCertificateQueryKind ResolveQueryKind(CtIngestionOperation operations)
    {
        if ((operations & CtIngestionOperation.GetDomainTreeCertificates) != 0)
        {
            return CtCertificateQueryKind.DomainTreeCertificates;
        }

        if ((operations & CtIngestionOperation.DiscoverSubdomains) != 0)
        {
            return CtCertificateQueryKind.DomainExpansion;
        }

        if ((operations & CtIngestionOperation.GetCertificateHistory) != 0)
        {
            return CtCertificateQueryKind.ExactHostHistory;
        }

        return CtCertificateQueryKind.ExactHostLatest;
    }

    private static bool QueryKindMatchesOperations(CtCertificateQueryKind queryKind, CtIngestionOperation operations)
    {
        return queryKind switch
        {
            CtCertificateQueryKind.DomainExpansion => operations == CtIngestionOperation.DiscoverSubdomains,
            CtCertificateQueryKind.ExactHostLatest => operations == CtIngestionOperation.GetLatestCertificate,
            CtCertificateQueryKind.ExactHostHistory => operations == CtIngestionOperation.GetCertificateHistory,
            CtCertificateQueryKind.DomainTreeCertificates => operations == CtIngestionOperation.GetDomainTreeCertificates,
            _ => false
        };
    }
}
