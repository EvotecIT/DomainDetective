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

    /// <summary>Last successful provider request time.</summary>
    public DateTimeOffset? LastSuccessUtc { get; init; }

    /// <summary>Last failed provider request time.</summary>
    public DateTimeOffset? LastFailureUtc { get; init; }

    /// <summary>Observed request latency percentile in milliseconds, when tracked by the caller.</summary>
    public double? ObservedP95LatencyMilliseconds { get; init; }

    /// <summary>Rolling transient failure ratio from zero to one, when tracked by the caller.</summary>
    public double? TransientFailureRatio { get; init; }
}
