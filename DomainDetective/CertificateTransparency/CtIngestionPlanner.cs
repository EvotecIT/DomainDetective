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
    /// Estimates a CT workload against a single provider profile.
    /// </summary>
    /// <param name="profile">Provider profile that supplies capabilities and rate limits.</param>
    /// <param name="workload">Workload to estimate.</param>
    /// <param name="nowUtc">Optional current time used for the completion estimate.</param>
    public static CtIngestionWorkloadEstimate EstimateWorkload(
        CtProviderProfile profile,
        CtIngestionWorkloadRequest workload,
        DateTimeOffset? nowUtc = null)
    {
        if (profile == null)
        {
            throw new ArgumentNullException(nameof(profile));
        }

        if (workload == null)
        {
            throw new ArgumentNullException(nameof(workload));
        }

        CtIngestionWorkloadRequest normalized = workload.Normalize();
        int domainRequests = EstimateDomainRequests(normalized);
        int hostRequests = EstimateHostRequests(normalized);
        int hydrationRequests = EstimateHydrationRequests(profile, normalized);
        int totalRequests = domainRequests + hostRequests + hydrationRequests;
        bool supportsWorkload = SupportsOperation(
            profile,
            normalized.Operations,
            normalized.RequireFullCertificate && hydrationRequests == 0);

        return new CtIngestionWorkloadEstimate
        {
            ProviderId = profile.ProviderId,
            ProviderSupportsWorkload = supportsWorkload,
            EstimatedRequestCount = totalRequests,
            EstimatedDomainRequests = domainRequests,
            EstimatedHostRequests = hostRequests,
            EstimatedHydrationRequests = hydrationRequests,
            Capacity = EstimateCapacity(profile, totalRequests, nowUtc),
            Note = BuildWorkloadNote(profile, normalized, supportsWorkload, hydrationRequests)
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

    private static int EstimateDomainRequests(CtIngestionWorkloadRequest workload)
    {
        bool usesDomainOperation =
            (workload.Operations & CtIngestionOperation.DiscoverSubdomains) != 0 ||
            (workload.Operations & CtIngestionOperation.GetDomainTreeCertificates) != 0;
        return usesDomainOperation
            ? workload.DomainCount * workload.RequestsPerDomain
            : 0;
    }

    private static int EstimateHostRequests(CtIngestionWorkloadRequest workload)
    {
        bool usesHostOperation =
            (workload.Operations & CtIngestionOperation.GetLatestCertificate) != 0 ||
            (workload.Operations & CtIngestionOperation.GetCertificateHistory) != 0;
        return usesHostOperation
            ? workload.HostCount * workload.RequestsPerHost
            : 0;
    }

    private static int EstimateHydrationRequests(CtProviderProfile profile, CtIngestionWorkloadRequest workload)
    {
        if (!workload.RequireFullCertificate ||
            workload.EstimatedCertificatesToHydrate <= 0 ||
            workload.HydrationRequestsPerCertificate <= 0 ||
            profile.Supports(CtProviderCapabilities.FullCertificateDer))
        {
            return 0;
        }

        return workload.EstimatedCertificatesToHydrate * workload.HydrationRequestsPerCertificate;
    }

    private static string BuildWorkloadNote(
        CtProviderProfile profile,
        CtIngestionWorkloadRequest workload,
        bool supportsWorkload,
        int hydrationRequests)
    {
        if (!supportsWorkload)
        {
            return "Provider does not advertise all requested CT capabilities.";
        }

        if (hydrationRequests > 0)
        {
            return "Provider requires additional certificate hydration requests to satisfy full-certificate output.";
        }

        if (workload.RequireFullCertificate &&
            profile.Supports(CtProviderCapabilities.FullCertificateDer))
        {
            return "Provider can return full certificate material for the requested workload.";
        }

        return "Provider can be used for the requested workload under the configured rate profile.";
    }
}
