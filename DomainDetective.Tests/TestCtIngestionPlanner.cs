using System;
using System.IO;
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
    }

    [Fact]
    public void WorkloadEstimateRejectsFullCertificateWhenProviderCannotHydrate()
    {
        CtProviderProfile profile = CtProviderProfiles.CreateCrtShHttp();
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
    }

    private static byte[] LoadPemCertificateDer(string fileName)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Data", fileName);
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
