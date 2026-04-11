using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Represents normalized CT query results from a provider.
/// </summary>
public sealed class CtCertificateQueryResult
{
    /// <summary>Provider that returned the result.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Certificate records returned by the provider.</summary>
    public IReadOnlyList<CtCertificateRecord> Certificates { get; init; } = Array.Empty<CtCertificateRecord>();

    /// <summary>Discovered DNS names returned by the provider.</summary>
    public IReadOnlyList<string> DiscoveredNames { get; init; } = Array.Empty<string>();

    /// <summary>Continuation token to request the next page, when supported.</summary>
    public string? ContinuationToken { get; init; }

    /// <summary>True when more provider data is available through the continuation token.</summary>
    public bool HasMore { get; init; }

    /// <summary>Provider runtime state observed during the query.</summary>
    public CtProviderRuntimeState? ProviderState { get; init; }

    /// <summary>Provider warnings or diagnostics useful for scheduling and retries.</summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();
}
