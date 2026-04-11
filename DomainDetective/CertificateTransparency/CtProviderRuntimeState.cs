using System;

namespace DomainDetective;

/// <summary>
/// Stores runtime health and cooldown state for a certificate transparency provider.
/// </summary>
public sealed class CtProviderRuntimeState
{
    /// <summary>Stable provider identifier.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Time before which the provider should not be queried.</summary>
    public DateTimeOffset? CooldownUntilUtc { get; init; }

    /// <summary>Number of consecutive provider failures observed by the caller.</summary>
    public int ConsecutiveFailures { get; init; }

    /// <summary>True when the provider reached a non-retryable failure and should not be queried until state is reset.</summary>
    public bool IsPermanentlyFailed { get; init; }

    /// <summary>Last successful provider request time.</summary>
    public DateTimeOffset? LastSuccessUtc { get; init; }

    /// <summary>Last failed provider request time.</summary>
    public DateTimeOffset? LastFailureUtc { get; init; }

    /// <summary>Observed request latency percentile in milliseconds, when tracked by the caller.</summary>
    public double? ObservedP95LatencyMilliseconds { get; init; }

    /// <summary>Rolling transient failure ratio from zero to one, when tracked by the caller.</summary>
    public double? TransientFailureRatio { get; init; }

    /// <summary>Total provider requests observed by the caller.</summary>
    public long TotalRequestCount { get; init; }

    /// <summary>Total successful provider requests observed by the caller.</summary>
    public long SuccessfulRequestCount { get; init; }

    /// <summary>Total transient provider failures observed by the caller.</summary>
    public long TransientFailureCount { get; init; }

    /// <summary>Total provider rate-limit responses observed by the caller.</summary>
    public long RateLimitedCount { get; init; }

    /// <summary>Total provider timeout responses observed by the caller.</summary>
    public long TimeoutCount { get; init; }

    /// <summary>Last HTTP status code observed for HTTP-backed providers.</summary>
    public int? LastHttpStatusCode { get; init; }

    /// <summary>Last provider error message observed by the caller.</summary>
    public string? LastError { get; init; }

    /// <summary>Last observed request latency in milliseconds.</summary>
    public double? LastObservedLatencyMilliseconds { get; init; }
}
