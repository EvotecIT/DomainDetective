using System;
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
        Assert.Equal(TimeSpan.FromSeconds(15 * 19_999), estimate.EstimatedMinimumDuration);
        Assert.Equal(now + TimeSpan.FromSeconds(15 * 19_999), estimate.EstimatedCompletionUtc);
        Assert.True(estimate.IsRateLimited);
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
}
