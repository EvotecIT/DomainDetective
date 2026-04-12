using System;

namespace DomainDetective;

/// <summary>
/// Captures the observed result of a certificate transparency provider request.
/// </summary>
public sealed class CtProviderRequestOutcome
{
    /// <summary>Provider that produced the outcome.</summary>
    public string ProviderId { get; init; } = string.Empty;

    /// <summary>Observed outcome kind.</summary>
    public CtProviderOutcomeKind OutcomeKind { get; init; }

    /// <summary>Time at which the outcome was observed.</summary>
    public DateTimeOffset? OccurredAtUtc { get; init; }

    /// <summary>Provider-requested retry delay, when supplied.</summary>
    public TimeSpan? RetryAfter { get; init; }

    /// <summary>Observed HTTP status code for HTTP-backed providers.</summary>
    public int? HttpStatusCode { get; init; }

    /// <summary>Observed request latency.</summary>
    public TimeSpan? Latency { get; init; }

    /// <summary>Provider error or diagnostic message.</summary>
    public string? Error { get; init; }

    /// <summary>When true, applies a cooldown for transient non-rate-limit failures.</summary>
    public bool CooldownOnTransientFailure { get; init; }
}
