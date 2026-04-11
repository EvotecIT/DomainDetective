using System;
using System.Collections.Generic;
using System.Linq;

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
        int maxConcurrentRequests = rateLimit.MaxConcurrentRequests.GetValueOrDefault(1);
        TimeSpan effectiveSpacing = ResolveEffectiveRequestSpacing(rateLimit);
        int firstRunRequestCount = EstimateFirstRunRequestCount(
            normalizedRequestCount,
            rateLimit.MaximumRequestsPerRun);
        int estimatedRunCount = EstimateRunCount(
            normalizedRequestCount,
            rateLimit.MaximumRequestsPerRun);
        int remainingRequestCount = Math.Max(0, normalizedRequestCount - firstRunRequestCount);
        TimeSpan spacingDuration = EstimateSpacingDuration(
            normalizedRequestCount,
            effectiveSpacing,
            rateLimit.EstimatedRequestDuration);
        int concurrencyWaveCount = EstimateConcurrencyWaveCount(normalizedRequestCount, maxConcurrentRequests);
        TimeSpan concurrencyDuration = MultiplyTimeSpan(rateLimit.EstimatedRequestDuration, concurrencyWaveCount);
        TimeSpan estimatedDuration = MaxTimeSpan(spacingDuration, concurrencyDuration);
        TimeSpan estimatedFirstRunDuration = EstimateDuration(
            firstRunRequestCount,
            effectiveSpacing,
            rateLimit.EstimatedRequestDuration,
            maxConcurrentRequests);
        DateTimeOffset startUtc = nowUtc ?? DateTimeOffset.UtcNow;

        return new CtProviderCapacityEstimate
        {
            ProviderId = profile.ProviderId,
            RequestCount = normalizedRequestCount,
            EffectiveRequestSpacing = effectiveSpacing,
            EstimatedRequestDuration = rateLimit.EstimatedRequestDuration,
            EstimatedMinimumDuration = estimatedDuration,
            EstimatedCompletionUtc = startUtc + estimatedDuration,
            MaxConcurrentRequests = maxConcurrentRequests,
            MaximumRequestsPerRun = rateLimit.MaximumRequestsPerRun,
            EstimatedRunCount = estimatedRunCount,
            FirstRunRequestCount = firstRunRequestCount,
            RemainingRequestCount = remainingRequestCount,
            EstimatedFirstRunDuration = estimatedFirstRunDuration,
            EstimatedFirstRunCompletionUtc = startUtc + estimatedFirstRunDuration,
            ConcurrencyWaveCount = concurrencyWaveCount,
            IsRateLimited = effectiveSpacing > TimeSpan.Zero,
            ExceedsRunBudget = estimatedRunCount > 1,
            IsConcurrencyLimited = normalizedRequestCount > maxConcurrentRequests &&
                concurrencyDuration >= spacingDuration
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
        bool supportsWorkload = SupportsWorkload(profile, normalized, hydrationRequests);
        CtProviderCapacityEstimate capacity = EstimateCapacity(profile, totalRequests, nowUtc);

        return new CtIngestionWorkloadEstimate
        {
            ProviderId = profile.ProviderId,
            ProviderSupportsWorkload = supportsWorkload,
            EstimatedRequestCount = totalRequests,
            EstimatedDomainRequests = domainRequests,
            EstimatedHostRequests = hostRequests,
            EstimatedHydrationRequests = hydrationRequests,
            Capacity = capacity,
            Note = BuildWorkloadNote(profile, normalized, supportsWorkload, hydrationRequests, capacity)
        };
    }

    /// <summary>
    /// Plans a CT workload for a single provider using capabilities, estimates, and runtime state.
    /// </summary>
    /// <param name="profile">Provider profile to evaluate.</param>
    /// <param name="workload">Workload requested by the caller.</param>
    /// <param name="state">Optional provider runtime state.</param>
    /// <param name="nowUtc">Optional current time used for planning.</param>
    public static CtProviderWorkPlan PlanProvider(
        CtProviderProfile profile,
        CtIngestionWorkloadRequest workload,
        CtProviderRuntimeState? state = null,
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

        CtIngestionWorkloadEstimate estimate = EstimateWorkload(profile, workload, nowUtc);
        if (!estimate.ProviderSupportsWorkload)
        {
            return new CtProviderWorkPlan
            {
                ProviderId = profile.ProviderId,
                Status = CtProviderPlanStatus.Unsupported,
                Estimate = estimate,
                Decision = null,
                Reason = estimate.Note ?? "Provider does not support the requested CT workload."
            };
        }

        CtProviderExecutionDecision decision = Decide(profile, state, nowUtc);
        if (!decision.CanRunNow)
        {
            return new CtProviderWorkPlan
            {
                ProviderId = profile.ProviderId,
                Status = CtProviderPlanStatus.Deferred,
                Estimate = estimate,
                Decision = decision,
                Reason = decision.Reason
            };
        }

        return new CtProviderWorkPlan
        {
            ProviderId = profile.ProviderId,
            Status = CtProviderPlanStatus.Ready,
            Estimate = estimate,
            Decision = decision,
            Reason = estimate.Note ?? decision.Reason
        };
    }

    /// <summary>
    /// Plans a CT workload across multiple providers in caller-supplied preference order.
    /// </summary>
    /// <param name="profiles">Provider profiles to evaluate.</param>
    /// <param name="workload">Workload requested by the caller.</param>
    /// <param name="states">Optional provider states keyed by provider identifier.</param>
    /// <param name="nowUtc">Optional current time used for planning.</param>
    public static IReadOnlyList<CtProviderWorkPlan> PlanProviders(
        IEnumerable<CtProviderProfile> profiles,
        CtIngestionWorkloadRequest workload,
        IReadOnlyDictionary<string, CtProviderRuntimeState>? states = null,
        DateTimeOffset? nowUtc = null)
    {
        if (profiles == null)
        {
            throw new ArgumentNullException(nameof(profiles));
        }

        if (workload == null)
        {
            throw new ArgumentNullException(nameof(workload));
        }

        var output = new List<CtProviderWorkPlan>();
        foreach (CtProviderProfile profile in profiles)
        {
            if (profile == null)
            {
                continue;
            }

            CtProviderRuntimeState? state = null;
            if (states != null &&
                !string.IsNullOrWhiteSpace(profile.ProviderId))
            {
                states.TryGetValue(profile.ProviderId, out state);
            }

            output.Add(PlanProvider(profile, workload, state, nowUtc));
        }

        return output;
    }

    /// <summary>
    /// Chooses the first provider that is ready in the supplied work plans.
    /// </summary>
    /// <param name="plans">Provider work plans in preference order.</param>
    public static CtProviderWorkPlan? ChooseFirstReadyProvider(IEnumerable<CtProviderWorkPlan> plans)
    {
        if (plans == null)
        {
            throw new ArgumentNullException(nameof(plans));
        }

        return plans.FirstOrDefault(plan => plan != null && plan.Status == CtProviderPlanStatus.Ready);
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

    private static bool SupportsWorkload(
        CtProviderProfile profile,
        CtIngestionWorkloadRequest workload,
        int hydrationRequests)
    {
        bool requiresFullCertificateMaterial = RequiresFullCertificateMaterial(workload);
        bool requiresFullCertificateFromProvider = requiresFullCertificateMaterial && hydrationRequests == 0;
        if (!SupportsOperation(profile, workload.Operations, requiresFullCertificateFromProvider))
        {
            return false;
        }

        if (!requiresFullCertificateMaterial || profile.Supports(CtProviderCapabilities.FullCertificateDer))
        {
            return true;
        }

        return hydrationRequests > 0 && profile.Supports(CtProviderCapabilities.CertificateHydration);
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

    private static TimeSpan EstimateSpacingDuration(
        int requestCount,
        TimeSpan effectiveSpacing,
        TimeSpan estimatedRequestDuration)
    {
        if (requestCount <= 0)
        {
            return TimeSpan.Zero;
        }

        if (effectiveSpacing <= TimeSpan.Zero)
        {
            return estimatedRequestDuration;
        }

        TimeSpan startSpacingDuration = MultiplyTimeSpan(effectiveSpacing, requestCount - 1);
        return AddTimeSpan(startSpacingDuration, estimatedRequestDuration);
    }

    private static TimeSpan EstimateDuration(
        int requestCount,
        TimeSpan effectiveSpacing,
        TimeSpan estimatedRequestDuration,
        int maxConcurrentRequests)
    {
        TimeSpan spacingDuration = EstimateSpacingDuration(
            requestCount,
            effectiveSpacing,
            estimatedRequestDuration);
        int concurrencyWaveCount = EstimateConcurrencyWaveCount(requestCount, maxConcurrentRequests);
        TimeSpan concurrencyDuration = MultiplyTimeSpan(estimatedRequestDuration, concurrencyWaveCount);
        return MaxTimeSpan(spacingDuration, concurrencyDuration);
    }

    private static int EstimateConcurrencyWaveCount(int requestCount, int maxConcurrentRequests)
    {
        if (requestCount <= 0)
        {
            return 0;
        }

        int normalizedConcurrency = Math.Max(1, maxConcurrentRequests);
        long waveCount = ((long)requestCount + normalizedConcurrency - 1) / normalizedConcurrency;
        return waveCount > int.MaxValue
            ? int.MaxValue
            : (int)waveCount;
    }

    private static int EstimateRunCount(int requestCount, int? maximumRequestsPerRun)
    {
        if (requestCount <= 0)
        {
            return 0;
        }

        if (!maximumRequestsPerRun.HasValue || maximumRequestsPerRun.Value <= 0)
        {
            return 1;
        }

        long runCount = ((long)requestCount + maximumRequestsPerRun.Value - 1) / maximumRequestsPerRun.Value;
        return runCount > int.MaxValue
            ? int.MaxValue
            : (int)runCount;
    }

    private static int EstimateFirstRunRequestCount(int requestCount, int? maximumRequestsPerRun)
    {
        if (requestCount <= 0)
        {
            return 0;
        }

        if (!maximumRequestsPerRun.HasValue || maximumRequestsPerRun.Value <= 0)
        {
            return requestCount;
        }

        return Math.Min(requestCount, maximumRequestsPerRun.Value);
    }

    private static TimeSpan MultiplyTimeSpan(TimeSpan value, int multiplier)
    {
        if (value <= TimeSpan.Zero || multiplier <= 0)
        {
            return TimeSpan.Zero;
        }

        double ticks = value.Ticks * (double)multiplier;
        if (ticks >= TimeSpan.MaxValue.Ticks)
        {
            return TimeSpan.MaxValue;
        }

        return TimeSpan.FromTicks((long)ticks);
    }

    private static TimeSpan AddTimeSpan(TimeSpan left, TimeSpan right)
    {
        if (left >= TimeSpan.MaxValue - right)
        {
            return TimeSpan.MaxValue;
        }

        return left + right;
    }

    private static TimeSpan MaxTimeSpan(TimeSpan left, TimeSpan right)
    {
        return left >= right
            ? left
            : right;
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
        if (!RequiresFullCertificateMaterial(workload) ||
            workload.EstimatedCertificatesToHydrate <= 0 ||
            workload.HydrationRequestsPerCertificate <= 0 ||
            profile.Supports(CtProviderCapabilities.FullCertificateDer) ||
            !profile.Supports(CtProviderCapabilities.CertificateHydration))
        {
            return 0;
        }

        return workload.EstimatedCertificatesToHydrate * workload.HydrationRequestsPerCertificate;
    }

    private static bool RequiresFullCertificateMaterial(CtIngestionWorkloadRequest workload)
    {
        if (!workload.RequireFullCertificate)
        {
            return false;
        }

        return (workload.Operations & CtIngestionOperation.GetLatestCertificate) != 0 ||
               (workload.Operations & CtIngestionOperation.GetCertificateHistory) != 0 ||
               (workload.Operations & CtIngestionOperation.GetDomainTreeCertificates) != 0;
    }

    private static string BuildWorkloadNote(
        CtProviderProfile profile,
        CtIngestionWorkloadRequest workload,
        bool supportsWorkload,
        int hydrationRequests,
        CtProviderCapacityEstimate capacity)
    {
        if (!supportsWorkload)
        {
            return "Provider does not advertise all requested CT capabilities.";
        }

        if (hydrationRequests > 0)
        {
            return "Provider requires additional certificate hydration requests to satisfy full-certificate output.";
        }

        if (capacity.ExceedsRunBudget)
        {
            return "Provider can be used, but the estimated workload exceeds the configured per-run budget and should be split across multiple logical runs.";
        }

        if (workload.RequireFullCertificate &&
            profile.Supports(CtProviderCapabilities.FullCertificateDer))
        {
            return "Provider can return full certificate material for the requested workload.";
        }

        return "Provider can be used for the requested workload under the configured rate profile.";
    }
}
