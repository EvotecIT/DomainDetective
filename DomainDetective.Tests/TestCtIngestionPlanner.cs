using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestCtIngestionPlanner
{
    [Fact]
    public void CrtShHttpDefaultUsesConservativePublicLimit()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();

        Assert.Equal(CtProviderProfiles.CrtShHttpProviderId, profile.ProviderId);
        Assert.Equal(5, profile.RateLimit.MaxRequestsPerMinute);
        Assert.Equal(1, profile.RateLimit.MaxConcurrentRequests);
        Assert.True(profile.RateLimit.MinimumRequestSpacing >= TimeSpan.FromSeconds(12));
        Assert.True(profile.Supports(CtProviderCapabilities.CertificateHydration));
        Assert.True(CtIngestionPlanner.SupportsOperation(
            profile,
            CtIngestionOperation.DiscoverSubdomains,
            requireFullCertificate: false));
        Assert.False(CtIngestionPlanner.SupportsOperation(
            profile,
            CtIngestionOperation.GetCertificateHistory,
            requireFullCertificate: true));
    }

    [Fact]
    public void CrtShSqlDefaultSupportsFullHistoryWithLimitedConcurrency()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShPostgreSql();

        Assert.Equal(CtProviderProfiles.CrtShPostgreSqlProviderId, profile.ProviderId);
        Assert.Equal(2, profile.RateLimit.MaxConcurrentRequests);
        Assert.True(CtIngestionPlanner.SupportsOperation(
            profile,
            CtIngestionOperation.GetCertificateHistory,
            requireFullCertificate: true));
        Assert.True(CtIngestionPlanner.SupportsOperation(
            profile,
            CtIngestionOperation.GetDomainTreeCertificates,
            requireFullCertificate: true));
    }

    [Fact]
    public void EstimateCapacityUsesMostConservativeSpacing()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);

        CtProviderCapacityEstimate estimate = CtIngestionPlanner.EstimateCapacity(profile, 20_000, now);

        Assert.Equal(TimeSpan.FromSeconds(15), estimate.EffectiveRequestSpacing);
        Assert.Equal(TimeSpan.FromSeconds(5), estimate.EstimatedRequestDuration);
        Assert.Equal(TimeSpan.FromSeconds(15 * 19_999 + 5), estimate.EstimatedMinimumDuration);
        Assert.Equal(now + TimeSpan.FromSeconds(15 * 19_999 + 5), estimate.EstimatedCompletionUtc);
        Assert.Null(estimate.MaximumRequestsPerRun);
        Assert.Equal(1, estimate.EstimatedRunCount);
        Assert.Equal(20_000, estimate.FirstRunRequestCount);
        Assert.Equal(0, estimate.RemainingRequestCount);
        Assert.Equal(estimate.EstimatedMinimumDuration, estimate.EstimatedFirstRunDuration);
        Assert.Equal(estimate.EstimatedCompletionUtc, estimate.EstimatedFirstRunCompletionUtc);
        Assert.False(estimate.ExceedsRunBudget);
        Assert.True(estimate.IsRateLimited);
        Assert.False(estimate.IsConcurrencyLimited);
    }

    [Fact]
    public void EstimateCapacityUsesRequestDurationWhenConcurrencyIsTheLimiter()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShPostgreSql();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);

        CtProviderCapacityEstimate estimate = CtIngestionPlanner.EstimateCapacity(profile, 20, now);

        Assert.Equal(TimeSpan.Zero, estimate.EffectiveRequestSpacing);
        Assert.Equal(TimeSpan.FromSeconds(10), estimate.EstimatedRequestDuration);
        Assert.Equal(2, estimate.MaxConcurrentRequests);
        Assert.Equal(10, estimate.ConcurrencyWaveCount);
        Assert.Equal(TimeSpan.FromSeconds(100), estimate.EstimatedMinimumDuration);
        Assert.Equal(now + TimeSpan.FromSeconds(100), estimate.EstimatedCompletionUtc);
        Assert.False(estimate.IsRateLimited);
        Assert.True(estimate.IsConcurrencyLimited);
    }

    [Fact]
    public void EstimateCapacityReportsRunBudgetSlices()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp(new CertificateInventoryCaptureOptions
        {
            PassiveCtCrtShMaximumRequestsPerRun = 100,
            PassiveCtCrtShMinimumSpacing = TimeSpan.FromSeconds(15),
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(30)
        });

        CtProviderCapacityEstimate estimate = CtIngestionPlanner.EstimateCapacity(profile, 250);

        Assert.Equal(100, estimate.MaximumRequestsPerRun);
        Assert.Equal(3, estimate.EstimatedRunCount);
        Assert.Equal(100, estimate.FirstRunRequestCount);
        Assert.Equal(150, estimate.RemainingRequestCount);
        Assert.Equal(TimeSpan.FromSeconds(15 * 99 + 5), estimate.EstimatedFirstRunDuration);
        Assert.True(estimate.ExceedsRunBudget);
    }

    [Fact]
    public void EstimateCapacityHandlesZeroRequests()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();

        CtProviderCapacityEstimate estimate = CtIngestionPlanner.EstimateCapacity(profile, 0);

        Assert.Equal(0, estimate.RequestCount);
        Assert.Equal(0, estimate.EstimatedRunCount);
        Assert.Equal(0, estimate.FirstRunRequestCount);
        Assert.Equal(TimeSpan.Zero, estimate.EstimatedMinimumDuration);
        Assert.Equal(TimeSpan.Zero, estimate.EstimatedFirstRunDuration);
    }

    [Fact]
    public void WorkloadEstimateReportsWhenProviderRunBudgetIsExceeded()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp(new CertificateInventoryCaptureOptions
        {
            PassiveCtCrtShMaximumRequestsPerRun = 10,
            PassiveCtCrtShMinimumSpacing = TimeSpan.FromSeconds(15),
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(30)
        });
        var workload = new CtIngestionWorkloadRequest
        {
            DomainCount = 25,
            Operations = CtIngestionOperation.DiscoverSubdomains,
            RequireFullCertificate = false
        };

        CtIngestionWorkloadEstimate estimate = CtIngestionPlanner.EstimateWorkload(profile, workload);

        Assert.True(estimate.ProviderSupportsWorkload);
        Assert.True(estimate.Capacity.ExceedsRunBudget);
        Assert.Contains("multiple logical runs", estimate.Note, StringComparison.Ordinal);
    }

    [Fact]
    public void DecideDefersProviderWhenCooldownIsActive()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var state = new CtProviderRuntimeState
        {
            ProviderId = profile.ProviderId,
            CooldownUntilUtc = now.AddMinutes(10)
        };

        CtProviderExecutionDecision decision = CtIngestionPlanner.Decide(profile, state, now);

        Assert.False(decision.CanRunNow);
        Assert.Equal(now.AddMinutes(10), decision.DeferUntilUtc);
        Assert.Equal(1, decision.MaxConcurrentRequests);
    }

    [Fact]
    public void DecideAllowsProviderWithoutActiveCooldown()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCertSpotter();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);

        CtProviderExecutionDecision decision = CtIngestionPlanner.Decide(profile, state: null, nowUtc: now);

        Assert.True(decision.CanRunNow);
        Assert.Null(decision.DeferUntilUtc);
        Assert.Equal(1, decision.MaxConcurrentRequests);
    }

    [Fact]
    public void CtCertificateRecordReportsFullCertificateAvailability()
    {
        var metadataOnly = new CtCertificateRecord
        {
            ProviderId = CtProviderProfiles.CrtShHttpProviderId,
            Sha256Fingerprint = "ABC"
        };
        var derBacked = new CtCertificateRecord
        {
            ProviderId = CtProviderProfiles.CertSpotterProviderId,
            CertificateDer = new byte[] { 1, 2, 3 }
        };

        Assert.False(metadataOnly.HasFullCertificate);
        Assert.True(derBacked.HasFullCertificate);
    }

    [Fact]
    public void ProviderProfilesCanReflectInventoryOptions()
    {
        var options = new CertificateInventoryCaptureOptions
        {
            PassiveCtCrtShMinimumSpacing = TimeSpan.FromSeconds(30),
            PassiveCtCertSpotterMinimumSpacing = TimeSpan.FromSeconds(45),
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(10),
            PassiveCtCrtShMaximumRequestsPerRun = 7,
            CrtShPostgreSqlMaximumConcurrentRequests = 3,
            CrtShPostgreSqlCommandTimeoutSeconds = 20,
            NativeCtRequestDelay = TimeSpan.FromMilliseconds(250),
            DiscoveryParallelism = 6,
            NativeCtMaxLogs = 4
        };

        CtProviderProfile crtSh = CtProviderProfiles.CreateCrtShHttp(options);
        CtProviderProfile certSpotter = CtProviderProfiles.CreateCertSpotter(options);
        CtProviderProfile sql = CtProviderProfiles.CreateCrtShPostgreSql(options);
        CtProviderProfile native = CtProviderProfiles.CreateNativeCtLogs(options);

        Assert.Equal(TimeSpan.FromSeconds(30), crtSh.RateLimit.MinimumRequestSpacing);
        Assert.Equal(7, crtSh.RateLimit.MaximumRequestsPerRun);
        Assert.Equal(TimeSpan.FromSeconds(45), certSpotter.RateLimit.MinimumRequestSpacing);
        Assert.Equal(3, sql.RateLimit.MaxConcurrentRequests);
        Assert.Equal(TimeSpan.FromSeconds(20), sql.RateLimit.RequestTimeout);
        Assert.Equal(4, native.RateLimit.MaxConcurrentRequests);
        Assert.Equal(TimeSpan.FromMilliseconds(250), native.RateLimit.MinimumRequestSpacing);
    }

    [Fact]
    public void WorkloadEstimateIncludesHydrationRequestsWhenProviderIsMetadataOnly()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        var workload = new CtIngestionWorkloadRequest
        {
            HostCount = 100,
            Operations = CtIngestionOperation.GetLatestCertificate,
            RequireFullCertificate = true,
            RequestsPerHost = 1,
            EstimatedCertificatesToHydrate = 100,
            HydrationRequestsPerCertificate = 1
        };

        CtIngestionWorkloadEstimate estimate = CtIngestionPlanner.EstimateWorkload(profile, workload);

        Assert.True(estimate.ProviderSupportsWorkload);
        Assert.Equal(100, estimate.EstimatedHostRequests);
        Assert.Equal(100, estimate.EstimatedHydrationRequests);
        Assert.Equal(200, estimate.EstimatedRequestCount);
        Assert.False(estimate.IsRequestCountSaturated);
    }

    [Fact]
    public void WorkloadEstimateRejectsFullCertificateWhenProviderCannotHydrate()
    {
        var profile = new CtProviderProfile
        {
            ProviderId = "metadata-only",
            Capabilities = CtProviderCapabilities.ExactHostLookup
        };
        var workload = new CtIngestionWorkloadRequest
        {
            HostCount = 100,
            Operations = CtIngestionOperation.GetLatestCertificate,
            RequireFullCertificate = true
        };

        CtIngestionWorkloadEstimate estimate = CtIngestionPlanner.EstimateWorkload(profile, workload);

        Assert.False(estimate.ProviderSupportsWorkload);
        Assert.Equal(100, estimate.EstimatedRequestCount);
    }

    [Fact]
    public void WorkloadEstimateSupportsHydrationCapableProviderWithoutKnownHydrationCount()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        var workload = new CtIngestionWorkloadRequest
        {
            HostCount = 100,
            Operations = CtIngestionOperation.GetLatestCertificate,
            RequireFullCertificate = true
        };

        CtIngestionWorkloadEstimate estimate = CtIngestionPlanner.EstimateWorkload(profile, workload);

        Assert.True(estimate.ProviderSupportsWorkload);
        Assert.Equal(0, estimate.EstimatedHydrationRequests);
        Assert.Contains("hydrate full certificate", estimate.Note, StringComparison.Ordinal);
    }

    [Fact]
    public void WorkloadEstimateSaturatesLargeRequestCounts()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShPostgreSql();
        var workload = new CtIngestionWorkloadRequest
        {
            HostCount = int.MaxValue,
            Operations = CtIngestionOperation.GetCertificateHistory,
            RequireFullCertificate = true,
            RequestsPerHost = 2
        };

        CtIngestionWorkloadEstimate estimate = CtIngestionPlanner.EstimateWorkload(profile, workload);

        Assert.True(estimate.IsRequestCountSaturated);
        Assert.Equal(int.MaxValue, estimate.EstimatedHostRequests);
        Assert.Equal(int.MaxValue, estimate.EstimatedRequestCount);
        Assert.Contains("capped", estimate.Note, StringComparison.Ordinal);
    }

    [Fact]
    public void CtCertificateRecordCanBeCreatedFromDer()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");

        CtCertificateRecord record = CtCertificateRecord.FromDer(
            CtProviderProfiles.CertSpotterProviderId,
            der,
            providerCertificateId: "cert-1");

        Assert.True(record.HasFullCertificate);
        Assert.Equal(CtProviderProfiles.CertSpotterProviderId, record.ProviderId);
        Assert.Equal("cert-1", record.ProviderCertificateId);
        Assert.NotEmpty(record.Sha256Fingerprint!);
        Assert.NotEmpty(record.Sha1Fingerprint!);
        Assert.NotEmpty(record.Subject!);
        Assert.NotEmpty(record.Issuer!);
        Assert.NotNull(record.NotBeforeUtc);
        Assert.NotNull(record.NotAfterUtc);
        Assert.NotEmpty(record.CertificateDer!);
        Assert.NotNull(record.IsSelfSigned);
        Assert.NotNull(record.WeakKey);
        Assert.NotNull(record.Sha1Signature);
        Assert.NotNull(record.AllowsServerAuthentication);
        Assert.NotNull(record.AllowsClientAuthentication);
        Assert.NotNull(record.AllowsSecureEmail);
        Assert.False(string.IsNullOrWhiteSpace(record.AuthenticationProfile));
    }

    [Fact]
    public void CtCertificateRecordNormalizesNullProviderIdToEmpty()
    {
        byte[] der = LoadPemCertificateDer("multi.pem");

        CtCertificateRecord record = CtCertificateRecord.FromDer(null!, der);

        Assert.Equal(string.Empty, record.ProviderId);
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void CtCertificateRecordDoesNotMarkP256EcdsaAsWeak()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=ecdsa.example.com", key, HashAlgorithmName.SHA256);
        var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
        subjectAlternativeNameBuilder.AddDnsName("ecdsa.example.com");
        request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        CtCertificateRecord record = CtCertificateRecord.FromDer(
            CtProviderProfiles.CertSpotterProviderId,
            certificate.Export(X509ContentType.Cert));

        Assert.False(record.WeakKey);
        Assert.True(record.IsSelfSigned);
        Assert.Contains("ecdsa.example.com", record.DnsNames, StringComparer.OrdinalIgnoreCase);
    }
#endif

    [Fact]
    public void RuntimeStateUpdaterAppliesRateLimitCooldown()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var outcome = new CtProviderRequestOutcome
        {
            ProviderId = profile.ProviderId,
            OutcomeKind = CtProviderOutcomeKind.RateLimited,
            OccurredAtUtc = now,
            RetryAfter = TimeSpan.FromMinutes(2),
            HttpStatusCode = 429,
            Error = "Too many requests"
        };

        CtProviderRuntimeState state = CtProviderRuntimeStateUpdater.Apply(null, profile, outcome);

        Assert.Equal(now.AddMinutes(2), state.CooldownUntilUtc);
        Assert.Equal(1, state.ConsecutiveFailures);
        Assert.Equal(1, state.TotalRequestCount);
        Assert.Equal(1, state.RateLimitedCount);
        Assert.Equal(0d, state.TransientFailureRatio);
        Assert.Equal(429, state.LastHttpStatusCode);
    }

    [Fact]
    public void RuntimeStateUpdaterClearsCooldownAfterSuccess()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var previous = new CtProviderRuntimeState
        {
            ProviderId = profile.ProviderId,
            CooldownUntilUtc = now.AddMinutes(2),
            ConsecutiveFailures = 3,
            IsPermanentlyFailed = true,
            TotalRequestCount = 3,
            TransientFailureCount = 3,
            LastFailureUtc = now.AddMinutes(-1)
        };
        var outcome = new CtProviderRequestOutcome
        {
            ProviderId = profile.ProviderId,
            OutcomeKind = CtProviderOutcomeKind.Success,
            OccurredAtUtc = now,
            Latency = TimeSpan.FromMilliseconds(250)
        };

        CtProviderRuntimeState state = CtProviderRuntimeStateUpdater.Apply(previous, profile, outcome);

        Assert.Null(state.CooldownUntilUtc);
        Assert.Equal(0, state.ConsecutiveFailures);
        Assert.False(state.IsPermanentlyFailed);
        Assert.Equal(4, state.TotalRequestCount);
        Assert.Equal(1, state.SuccessfulRequestCount);
        Assert.Equal(now, state.LastSuccessUtc);
        Assert.Equal(250d, state.LastObservedLatencyMilliseconds);
    }

    [Fact]
    public void RuntimeStateUpdaterClearsPermanentFailedFlagAfterSuccess()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var previous = new CtProviderRuntimeState
        {
            ProviderId = profile.ProviderId,
            IsPermanentlyFailed = true,
            TotalRequestCount = 1,
            LastFailureUtc = now.AddMinutes(-1)
        };
        var outcome = new CtProviderRequestOutcome
        {
            ProviderId = profile.ProviderId,
            OutcomeKind = CtProviderOutcomeKind.Success,
            OccurredAtUtc = now
        };

        CtProviderRuntimeState state = CtProviderRuntimeStateUpdater.Apply(previous, profile, outcome);

        Assert.False(state.IsPermanentlyFailed);
        Assert.Equal(now, state.LastSuccessUtc);
    }

    [Fact]
    public void RuntimeStateUpdaterMarksPermanentFailure()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCertSpotter();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var outcome = new CtProviderRequestOutcome
        {
            ProviderId = profile.ProviderId,
            OutcomeKind = CtProviderOutcomeKind.PermanentFailure,
            OccurredAtUtc = now,
            HttpStatusCode = 401,
            Error = "Invalid API token"
        };

        CtProviderRuntimeState state = CtProviderRuntimeStateUpdater.Apply(null, profile, outcome);
        CtProviderExecutionDecision decision = CtIngestionPlanner.Decide(profile, state, now);

        Assert.True(state.IsPermanentlyFailed);
        Assert.Null(state.CooldownUntilUtc);
        Assert.Equal(1, state.ConsecutiveFailures);
        Assert.Equal(0d, state.TransientFailureRatio);
        Assert.False(decision.CanRunNow);
        Assert.Contains("permanent failure", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecideAllowsProviderAfterRecoverySuccess()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var state = new CtProviderRuntimeState
        {
            ProviderId = profile.ProviderId,
            LastFailureUtc = now.AddMinutes(-1),
            LastSuccessUtc = now,
            TransientFailureRatio = 0.5d,
            TotalRequestCount = 2,
            SuccessfulRequestCount = 1,
            TransientFailureCount = 1
        };

        CtProviderExecutionDecision decision = CtIngestionPlanner.Decide(profile, state, now);

        Assert.True(decision.CanRunNow);
        Assert.Null(decision.DeferUntilUtc);
    }

    [Fact]
    public void DecideUsesConfiguredFailureRatioThreshold()
    {
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var profile = new CtProviderProfile
        {
            ProviderId = "custom",
            RateLimit = new CtProviderRateLimitProfile
            {
                CooldownAfterRateLimit = TimeSpan.FromMinutes(5),
                TransientFailureRatioCooldownThreshold = 0.75d
            }
        };
        var state = new CtProviderRuntimeState
        {
            ProviderId = profile.ProviderId,
            LastFailureUtc = now,
            TransientFailureRatio = 0.6d
        };

        CtProviderExecutionDecision decision = CtIngestionPlanner.Decide(profile, state, now);

        Assert.True(decision.CanRunNow);
        Assert.Null(decision.DeferUntilUtc);
    }

    [Fact]
    public void PlanProvidersChoosesSqlForFullCertificateHistory()
    {
        CtProviderProfile http = CtProviderProfiles.CreateCrtShHttp();
        CtProviderProfile sql = CtProviderProfiles.CreateCrtShPostgreSql();
        var workload = new CtIngestionWorkloadRequest
        {
            HostCount = 10,
            Operations = CtIngestionOperation.GetCertificateHistory,
            RequireFullCertificate = true
        };

        IReadOnlyList<CtProviderWorkPlan> plans = CtIngestionPlanner.PlanProviders(
            new[] { http, sql },
            workload);
        CtProviderWorkPlan? selected = CtIngestionPlanner.ChooseFirstReadyProvider(plans);

        Assert.Equal(CtProviderPlanStatus.Unsupported, plans[0].Status);
        Assert.Equal(CtProviderPlanStatus.Ready, plans[1].Status);
        Assert.NotNull(selected);
        Assert.Equal(CtProviderProfiles.CrtShPostgreSqlProviderId, selected!.ProviderId);
    }

    [Fact]
    public void PlanProvidersDefersProviderInCooldown()
    {
        CtProviderProfile http = CtProviderProfiles.CreateCrtShHttp();
        DateTimeOffset now = new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero);
        var workload = new CtIngestionWorkloadRequest
        {
            DomainCount = 1,
            Operations = CtIngestionOperation.DiscoverSubdomains
        };
        var states = new Dictionary<string, CtProviderRuntimeState>(StringComparer.OrdinalIgnoreCase)
        {
            [http.ProviderId] = new CtProviderRuntimeState
            {
                ProviderId = http.ProviderId,
                CooldownUntilUtc = now.AddMinutes(5)
            }
        };

        IReadOnlyList<CtProviderWorkPlan> plans = CtIngestionPlanner.PlanProviders(
            new[] { http },
            workload,
            states,
            now);

        Assert.Single(plans);
        Assert.Equal(CtProviderPlanStatus.Deferred, plans[0].Status);
        Assert.Equal(now.AddMinutes(5), plans[0].Decision?.DeferUntilUtc);
    }

    private static byte[] LoadPemCertificateDer(string fileName)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Data", Path.GetFileName(fileName));
        string pem = File.ReadAllText(path);
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        int start = pem.IndexOf(begin, StringComparison.Ordinal);
        int finish = pem.IndexOf(end, StringComparison.Ordinal);
        Assert.True(start >= 0 && finish > start, "Expected PEM certificate fixture.");
        string base64 = pem.Substring(start + begin.Length, finish - start - begin.Length)
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty)
            .Trim();
        return Convert.FromBase64String(base64);
    }
}
