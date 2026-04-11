using System;

namespace DomainDetective;

/// <summary>
/// Plans certificate transparency provider work using capabilities and configured limits.
/// </summary>
public static class CtIngestionPlanner
{
    /// <summary>
    /// Estimates the minimum duration for a number of provider requests.
    /// </summary>
    /// <param name="profile">Provider profile that supplies rate-limit settings.</param>
    /// <param name="requestCount">Number of provider requests to issue.</param>
    /// <param name="nowUtc">Optional current time used for the completion estimate.</param>
    public static CtProviderCapacityEstimate EstimateCapacity(
        CtProviderProfile profile,
        int requestCount,
        DateTimeOffset? nowUtc = null)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        int normalizedRequestCount = Math.Max(0, requestCount);
        CtProviderRateLimitProfile rateLimit = (profile.RateLimit ?? new CtProviderRateLimitProfile()).Normalize();
        TimeSpan effectiveSpacing = ResolveEffectiveRequestSpacing(rateLimit);
        TimeSpan estimatedDuration = normalizedRequestCount <= 1
            ? TimeSpan.Zero
            : TimeSpan.FromTicks(effectiveSpacing.Ticks * (normalizedRequestCount - 1));
        DateTimeOffset startUtc = nowUtc ?? DateTimeOffset.UtcNow;

        return new CtProviderCapacityEstimate
        {
            ProviderId = profile.ProviderId,
            RequestCount = normalizedRequestCount,
            EffectiveRequestSpacing = effectiveSpacing,
            EstimatedMinimumDuration = estimatedDuration,
            EstimatedCompletionUtc = startUtc + estimatedDuration,
            MaxConcurrentRequests = rateLimit.MaxConcurrentRequests.GetValueOrDefault(1),
            IsRateLimited = effectiveSpacing > TimeSpan.Zero
        };
    }

    /// <summary>
    /// Determines whether a provider should run now or be deferred.
    /// </summary>
    /// <param name="profile">Provider profile that supplies safety settings.</param>
    /// <param name="state">Optional persisted provider runtime state.</param>
    /// <param name="nowUtc">Optional current time used for decision evaluation.</param>
    public static CtProviderExecutionDecision Decide(
        CtProviderProfile profile,
        CtProviderRuntimeState? state,
        DateTimeOffset? nowUtc = null)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        DateTimeOffset effectiveNowUtc = nowUtc ?? DateTimeOffset.UtcNow;
        CtProviderRateLimitProfile rateLimit = (profile.RateLimit ?? new CtProviderRateLimitProfile()).Normalize();
        if (state?.CooldownUntilUtc.HasValue == true &&
            state.CooldownUntilUtc.Value > effectiveNowUtc)
        {
            return new CtProviderExecutionDecision
            {
                ProviderId = profile.ProviderId,
                CanRunNow = false,
                DeferUntilUtc = state.CooldownUntilUtc,
                MaxConcurrentRequests = rateLimit.MaxConcurrentRequests.GetValueOrDefault(1),
                Reason = "Provider is cooling down after earlier rate limits or transient failures."
            };
        }

        if (state != null &&
            state.TransientFailureRatio.HasValue &&
            state.TransientFailureRatio.Value >= 0.5d &&
            state.LastFailureUtc.HasValue)
        {
            DateTimeOffset deferUntilUtc = state.LastFailureUtc.Value + rateLimit.CooldownAfterRateLimit;
            if (deferUntilUtc > effectiveNowUtc)
            {
                return new CtProviderExecutionDecision
                {
                    ProviderId = profile.ProviderId,
                    CanRunNow = false,
                    DeferUntilUtc = deferUntilUtc,
                    MaxConcurrentRequests = rateLimit.MaxConcurrentRequests.GetValueOrDefault(1),
                    Reason = "Provider failure ratio is high; deferred according to the configured cooldown."
                };
            }
        }

        return new CtProviderExecutionDecision
        {
            ProviderId = profile.ProviderId,
            CanRunNow = true,
            DeferUntilUtc = null,
            MaxConcurrentRequests = rateLimit.MaxConcurrentRequests.GetValueOrDefault(1),
            Reason = "Provider is eligible to run under the current profile."
        };
    }

    /// <summary>
    /// Determines whether a provider can satisfy a requested CT operation with full certificates.
    /// </summary>
    /// <param name="profile">Provider profile to evaluate.</param>
    /// <param name="operation">Operation requested by the caller.</param>
    /// <param name="requireFullCertificate">Whether the caller requires full certificate DER bytes.</param>
    public static bool SupportsOperation(
        CtProviderProfile profile,
        CtIngestionOperation operation,
        bool requireFullCertificate)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        CtProviderCapabilities required = CtProviderCapabilities.None;
        if ((operation & CtIngestionOperation.DiscoverSubdomains) != 0)
        {
            required |= CtProviderCapabilities.SubdomainExpansion;
        }

        if ((operation & CtIngestionOperation.GetLatestCertificate) != 0)
        {
            required |= CtProviderCapabilities.ExactHostLookup;
        }

        if ((operation & CtIngestionOperation.GetCertificateHistory) != 0)
        {
            required |= CtProviderCapabilities.ExactHostLookup | CtProviderCapabilities.CertificateHistory;
        }

        if ((operation & CtIngestionOperation.GetDomainTreeCertificates) != 0)
        {
            required |= CtProviderCapabilities.SubdomainExpansion | CtProviderCapabilities.DomainTreeHistory;
        }

        if (requireFullCertificate)
        {
            required |= CtProviderCapabilities.FullCertificateDer;
        }

        return profile.Supports(required);
    }

    private static TimeSpan ResolveEffectiveRequestSpacing(CtProviderRateLimitProfile rateLimit)
    {
        TimeSpan spacing = rateLimit.MinimumRequestSpacing;
        if (rateLimit.MaxRequestsPerMinute.HasValue && rateLimit.MaxRequestsPerMinute.Value > 0)
        {
            long ticks = TimeSpan.FromMinutes(1).Ticks / rateLimit.MaxRequestsPerMinute.Value;
            var rateLimitSpacing = TimeSpan.FromTicks(ticks);
            if (rateLimitSpacing > spacing)
            {
                spacing = rateLimitSpacing;
            }
        }

        return spacing;
    }
}
