using System;

namespace DomainDetective;

/// <summary>
/// Estimates how long provider work should take under a configured CT provider profile.
/// </summary>
public sealed class CtProviderCapacityEstimate
{
    /// <summary>Provider identifier used for the estimate.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Number of provider requests included in the estimate.</summary>
    public int RequestCount { get; init; }

    /// <summary>Effective spacing between request starts after applying rate-limit settings.</summary>
    public TimeSpan EffectiveRequestSpacing { get; init; }

    /// <summary>Estimated minimum wall-clock duration for the requested provider calls.</summary>
    public TimeSpan EstimatedMinimumDuration { get; init; }

    /// <summary>Estimated completion time when starting from the provided current time.</summary>
    public DateTimeOffset EstimatedCompletionUtc { get; init; }

    /// <summary>Safe concurrency to use for provider requests.</summary>
    public int MaxConcurrentRequests { get; init; } = 1;

    /// <summary>True when the estimate is dominated by request pacing rather than only concurrency.</summary>
    public bool IsRateLimited { get; init; }
}
