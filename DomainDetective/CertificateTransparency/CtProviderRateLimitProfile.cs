using System;

namespace DomainDetective;

/// <summary>
/// Configures safe request pacing for a certificate transparency provider.
/// </summary>
public sealed class CtProviderRateLimitProfile
{
    /// <summary>Maximum requests allowed per minute for the provider, when known.</summary>
    public int? MaxRequestsPerMinute { get; init; }

    /// <summary>Maximum concurrent requests or connections for the provider, when known.</summary>
    public int? MaxConcurrentRequests { get; init; }

    /// <summary>Minimum spacing between request starts for the provider.</summary>
    public TimeSpan MinimumRequestSpacing { get; init; } = TimeSpan.Zero;

    /// <summary>Per-request timeout used for provider calls.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Expected wall-clock duration for one provider request when estimating throughput.</summary>
    public TimeSpan EstimatedRequestDuration { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Base retry delay used after transient provider failures.</summary>
    public TimeSpan RetryBaseDelay { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Maximum retry delay used after transient provider failures.</summary>
    public TimeSpan RetryMaxDelay { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Default cooldown after a rate limit or repeated provider failure.</summary>
    public TimeSpan CooldownAfterRateLimit { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Optional request budget for a single logical run. Null means no run-local cap.</summary>
    public int? MaximumRequestsPerRun { get; init; }

    /// <summary>Returns a normalized copy of the rate limit profile.</summary>
    public CtProviderRateLimitProfile Normalize()
    {
        int? maxRequestsPerMinute = MaxRequestsPerMinute.HasValue
            ? Math.Max(1, MaxRequestsPerMinute.Value)
            : null;
        int? maxConcurrentRequests = MaxConcurrentRequests.HasValue
            ? Math.Max(1, MaxConcurrentRequests.Value)
            : null;
        int? maximumRequestsPerRun = MaximumRequestsPerRun.HasValue
            ? Math.Max(1, MaximumRequestsPerRun.Value)
            : null;

        TimeSpan minimumRequestSpacing = MinimumRequestSpacing < TimeSpan.Zero
            ? TimeSpan.Zero
            : MinimumRequestSpacing;
        TimeSpan requestTimeout = RequestTimeout <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(30)
            : RequestTimeout;
        TimeSpan estimatedRequestDuration = EstimatedRequestDuration <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(1)
            : EstimatedRequestDuration;
        TimeSpan retryBaseDelay = RetryBaseDelay < TimeSpan.Zero
            ? TimeSpan.Zero
            : RetryBaseDelay;
        TimeSpan retryMaxDelay = RetryMaxDelay <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(30)
            : RetryMaxDelay;
        if (retryMaxDelay < retryBaseDelay)
        {
            retryMaxDelay = retryBaseDelay;
        }

        TimeSpan cooldownAfterRateLimit = CooldownAfterRateLimit < TimeSpan.Zero
            ? TimeSpan.Zero
            : CooldownAfterRateLimit;

        return new CtProviderRateLimitProfile
        {
            MaxRequestsPerMinute = maxRequestsPerMinute,
            MaxConcurrentRequests = maxConcurrentRequests,
            MinimumRequestSpacing = minimumRequestSpacing,
            RequestTimeout = requestTimeout,
            EstimatedRequestDuration = estimatedRequestDuration,
            RetryBaseDelay = retryBaseDelay,
            RetryMaxDelay = retryMaxDelay,
            CooldownAfterRateLimit = cooldownAfterRateLimit,
            MaximumRequestsPerRun = maximumRequestsPerRun
        };
    }
}
