using System;

namespace DomainDetective;

/// <summary>
/// Applies provider request outcomes to certificate transparency provider runtime state.
/// </summary>
public static class CtProviderRuntimeStateUpdater
{
    /// <summary>
    /// Creates an updated provider runtime state from an observed request outcome.
    /// </summary>
    /// <param name="previous">Previous provider state, when available.</param>
    /// <param name="profile">Provider profile used to determine cooldown defaults.</param>
    /// <param name="outcome">Observed provider request outcome.</param>
    public static CtProviderRuntimeState Apply(
        CtProviderRuntimeState? previous,
        CtProviderProfile profile,
        CtProviderRequestOutcome outcome)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        if (outcome == null)
        {
            throw new ArgumentNullException(nameof(outcome));
        }

        DateTimeOffset occurredAtUtc = outcome.OccurredAtUtc ?? DateTimeOffset.UtcNow;
        CtProviderRateLimitProfile rateLimit = (profile.RateLimit ?? new CtProviderRateLimitProfile()).Normalize();
        bool success = outcome.OutcomeKind == CtProviderOutcomeKind.Success;
        bool transientFailure = outcome.OutcomeKind == CtProviderOutcomeKind.TransientFailure ||
                                outcome.OutcomeKind == CtProviderOutcomeKind.Timeout;
        bool rateLimited = outcome.OutcomeKind == CtProviderOutcomeKind.RateLimited;
        bool timeout = outcome.OutcomeKind == CtProviderOutcomeKind.Timeout;
        bool permanentFailure = outcome.OutcomeKind == CtProviderOutcomeKind.PermanentFailure;
        long totalRequestCount = checked((previous?.TotalRequestCount ?? 0L) + 1L);
        long successfulRequestCount = checked((previous?.SuccessfulRequestCount ?? 0L) + (success ? 1L : 0L));
        long transientFailureCount = checked((previous?.TransientFailureCount ?? 0L) + (transientFailure ? 1L : 0L));
        long rateLimitedCount = checked((previous?.RateLimitedCount ?? 0L) + (rateLimited ? 1L : 0L));
        long timeoutCount = checked((previous?.TimeoutCount ?? 0L) + (timeout ? 1L : 0L));
        int consecutiveFailures = success ? 0 : checked((previous?.ConsecutiveFailures ?? 0) + 1);

        DateTimeOffset? cooldownUntilUtc = ResolveCooldownUntilUtc(previous, rateLimit, outcome, occurredAtUtc);
        return new CtProviderRuntimeState
        {
            ProviderId = string.IsNullOrWhiteSpace(outcome.ProviderId) ? profile.ProviderId : outcome.ProviderId,
            CooldownUntilUtc = cooldownUntilUtc,
            ConsecutiveFailures = consecutiveFailures,
            IsPermanentlyFailed = !success && (permanentFailure || previous?.IsPermanentlyFailed == true),
            LastSuccessUtc = success ? occurredAtUtc : previous?.LastSuccessUtc,
            LastFailureUtc = success ? previous?.LastFailureUtc : occurredAtUtc,
            ObservedP95LatencyMilliseconds = previous?.ObservedP95LatencyMilliseconds,
            TransientFailureRatio = (double)transientFailureCount / totalRequestCount,
            TotalRequestCount = totalRequestCount,
            SuccessfulRequestCount = successfulRequestCount,
            TransientFailureCount = transientFailureCount,
            RateLimitedCount = rateLimitedCount,
            TimeoutCount = timeoutCount,
            LastHttpStatusCode = outcome.HttpStatusCode,
            LastError = success ? null : outcome.Error,
            LastObservedLatencyMilliseconds = outcome.Latency?.TotalMilliseconds
        };
    }

    private static DateTimeOffset? ResolveCooldownUntilUtc(
        CtProviderRuntimeState? previous,
        CtProviderRateLimitProfile rateLimit,
        CtProviderRequestOutcome outcome,
        DateTimeOffset occurredAtUtc)
    {
        if (outcome.OutcomeKind == CtProviderOutcomeKind.Success)
        {
            return null;
        }

        if (outcome.OutcomeKind == CtProviderOutcomeKind.RateLimited)
        {
            TimeSpan cooldown = outcome.RetryAfter.HasValue && outcome.RetryAfter.Value > TimeSpan.Zero
                ? outcome.RetryAfter.Value
                : rateLimit.CooldownAfterRateLimit;
            return Max(previous?.CooldownUntilUtc, occurredAtUtc + cooldown);
        }

        if (outcome.OutcomeKind == CtProviderOutcomeKind.TransientFailure &&
            outcome.CooldownOnTransientFailure)
        {
            return Max(previous?.CooldownUntilUtc, occurredAtUtc + rateLimit.CooldownAfterRateLimit);
        }

        if (outcome.OutcomeKind == CtProviderOutcomeKind.Timeout &&
            outcome.CooldownOnTransientFailure)
        {
            return Max(previous?.CooldownUntilUtc, occurredAtUtc + rateLimit.CooldownAfterRateLimit);
        }

        return previous?.CooldownUntilUtc;
    }

    private static DateTimeOffset? Max(DateTimeOffset? left, DateTimeOffset right)
    {
        if (!left.HasValue || right > left.Value)
        {
            return right;
        }

        return left.Value;
    }
}
