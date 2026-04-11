using System;

namespace DomainDetective;

/// <summary>
/// Represents a provider-specific certificate transparency workload estimate.
/// </summary>
public sealed class CtIngestionWorkloadEstimate
{
    /// <summary>Provider identifier used for the estimate.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>True when the provider advertises the capabilities requested by the workload.</summary>
    public bool ProviderSupportsWorkload { get; init; }

    /// <summary>Total estimated request count for the provider.</summary>
    public int EstimatedRequestCount { get; init; }

    /// <summary>Estimated domain-level provider requests.</summary>
    public int EstimatedDomainRequests { get; init; }

    /// <summary>Estimated exact-host provider requests.</summary>
    public int EstimatedHostRequests { get; init; }

    /// <summary>Estimated follow-up certificate hydration provider requests.</summary>
    public int EstimatedHydrationRequests { get; init; }

    /// <summary>Provider capacity estimate for the total request count.</summary>
    public CtProviderCapacityEstimate Capacity { get; init; } = new();

    /// <summary>Human-readable planning note.</summary>
    public string? Note { get; init; }
}
