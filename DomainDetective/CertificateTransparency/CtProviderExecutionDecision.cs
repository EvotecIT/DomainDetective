using System;

namespace DomainDetective;

/// <summary>
/// Describes whether a certificate transparency provider should run now or be deferred.
/// </summary>
public sealed class CtProviderExecutionDecision
{
    /// <summary>Provider identifier that was evaluated.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Whether the provider can be used immediately.</summary>
    public bool CanRunNow { get; init; }

    /// <summary>Time after which deferred provider work may be retried.</summary>
    public DateTimeOffset? DeferUntilUtc { get; init; }

    /// <summary>Safe concurrency to use for this provider decision.</summary>
    public int MaxConcurrentRequests { get; init; } = 1;

    /// <summary>Human-readable reason for the decision.</summary>
    public string Reason { get; init; } = string.Empty;
}
