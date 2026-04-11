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

    /// <summary>Expected wall-clock duration for one provider request used by the estimate.</summary>
    public TimeSpan EstimatedRequestDuration { get; init; }

    /// <summary>Estimated minimum wall-clock duration for the requested provider calls.</summary>
    public TimeSpan EstimatedMinimumDuration { get; init; }

    /// <summary>Estimated completion time when starting from the provided current time.</summary>
    public DateTimeOffset EstimatedCompletionUtc { get; init; }

    /// <summary>Safe concurrency to use for provider requests.</summary>
    public int MaxConcurrentRequests { get; init; } = 1;

    /// <summary>Optional provider request budget for one logical run.</summary>
    public int? MaximumRequestsPerRun { get; init; }

    /// <summary>Estimated number of logical runs needed for the requested provider calls.</summary>
    public int EstimatedRunCount { get; init; }

    /// <summary>Estimated request count in the first logical run after applying the run budget.</summary>
    public int FirstRunRequestCount { get; init; }

    /// <summary>Estimated request count remaining after the first logical run.</summary>
    public int RemainingRequestCount { get; init; }

    /// <summary>Estimated wall-clock duration for the first logical run.</summary>
    public TimeSpan EstimatedFirstRunDuration { get; init; }

    /// <summary>Estimated completion time for the first logical run.</summary>
    public DateTimeOffset EstimatedFirstRunCompletionUtc { get; init; }

    /// <summary>Number of request waves needed under the configured concurrency limit.</summary>
    public int ConcurrencyWaveCount { get; init; }

    /// <summary>True when the estimate is dominated by request pacing rather than only concurrency.</summary>
    public bool IsRateLimited { get; init; }

    /// <summary>True when the request count exceeds the provider budget for one logical run.</summary>
    public bool ExceedsRunBudget { get; init; }

    /// <summary>True when request duration and concurrency shape the minimum duration estimate.</summary>
    public bool IsConcurrencyLimited { get; init; }
}
