using System;

namespace DomainDetective;

/// <summary>
/// Configures safe request pacing for a certificate transparency provider.
/// </summary>
public sealed class CtProviderRateLimitProfile
{
    /// <summary>Maximum requests allowed per minute for the provider, when known.</summary>
    public int? MaxRequestsPerMinute { get; init; }

    /// <summary>Maximum requests allowed per second for the provider, when known.</summary>
    public int? MaxRequestsPerSecond { get; init; }

    /// <summary>Maximum requests allowed per hour for the provider, when known.</summary>
    public int? MaxRequestsPerHour { get; init; }

    /// <summary>Maximum exact-host CT queries allowed per hour for the provider, when known.</summary>
    public int? MaxSingleHostnameQueriesPerHour { get; init; }

    /// <summary>Maximum domain-tree or subdomain-expansion CT queries allowed per hour for the provider, when known.</summary>
    public int? MaxFullDomainQueriesPerHour { get; init; }

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

    /// <summary>Default cooldown after a rate limit or a high transient-failure ratio.</summary>
    public TimeSpan CooldownAfterRateLimit { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Transient failure ratio from zero to one at which provider execution should cool down.</summary>
    public double TransientFailureRatioCooldownThreshold { get; init; } = 0.5d;

    /// <summary>Optional request budget for a single logical run. Null means no run-local cap.</summary>
    public int? MaximumRequestsPerRun { get; init; }

    /// <summary>Returns a normalized copy of the rate limit profile.</summary>
    public CtProviderRateLimitProfile Normalize()
    {
        int? maxRequestsPerMinute = MaxRequestsPerMinute.HasValue
            ? Math.Max(1, MaxRequestsPerMinute.Value)
            : null;
        int? maxRequestsPerSecond = MaxRequestsPerSecond.HasValue
            ? Math.Max(1, MaxRequestsPerSecond.Value)
            : null;
        int? maxRequestsPerHour = MaxRequestsPerHour.HasValue
            ? Math.Max(1, MaxRequestsPerHour.Value)
            : null;
        int? maxSingleHostnameQueriesPerHour = MaxSingleHostnameQueriesPerHour.HasValue
            ? Math.Max(1, MaxSingleHostnameQueriesPerHour.Value)
            : null;
        int? maxFullDomainQueriesPerHour = MaxFullDomainQueriesPerHour.HasValue
            ? Math.Max(1, MaxFullDomainQueriesPerHour.Value)
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
        double transientFailureRatioCooldownThreshold =
            double.IsNaN(TransientFailureRatioCooldownThreshold) ||
            double.IsInfinity(TransientFailureRatioCooldownThreshold) ||
            TransientFailureRatioCooldownThreshold < 0d
                ? 0.5d
                : Math.Min(1d, TransientFailureRatioCooldownThreshold);

        return new CtProviderRateLimitProfile
        {
            MaxRequestsPerMinute = maxRequestsPerMinute,
            MaxRequestsPerSecond = maxRequestsPerSecond,
            MaxRequestsPerHour = maxRequestsPerHour,
            MaxSingleHostnameQueriesPerHour = maxSingleHostnameQueriesPerHour,
            MaxFullDomainQueriesPerHour = maxFullDomainQueriesPerHour,
            MaxConcurrentRequests = maxConcurrentRequests,
            MinimumRequestSpacing = minimumRequestSpacing,
            RequestTimeout = requestTimeout,
            EstimatedRequestDuration = estimatedRequestDuration,
            RetryBaseDelay = retryBaseDelay,
            RetryMaxDelay = retryMaxDelay,
            CooldownAfterRateLimit = cooldownAfterRateLimit,
            TransientFailureRatioCooldownThreshold = transientFailureRatioCooldownThreshold,
            MaximumRequestsPerRun = maximumRequestsPerRun
        };
    }
}
