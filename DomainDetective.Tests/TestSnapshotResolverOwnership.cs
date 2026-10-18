using System.Reflection;
using DnsClientX;

namespace DomainDetective.Tests;

public class TestSnapshotResolverOwnership {
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void FilteredAndSourceResolversHaveIndependentLifetimes(bool retireSource, bool replace) {
        using var source = new DomainHealthCheck();
        source.DnsConfiguration.UserAgent = "SyntheticSnapshotAgent";
        source.DnsConfiguration.ResolverMaxConcurrency = 3;
        source.DnsConfiguration.MaxCacheTtl = TimeSpan.FromSeconds(37);
        source.DnsConfiguration.DnsEndpoints.Add(DnsEndpoint.Cloudflare);
        using var snapshot = source.FilterAnalyses(new[] { HealthCheckType.NS });
        var retired = retireSource ? source : snapshot;
        var survivor = retireSource ? snapshot : source;
        if (replace) { retired.DnsConfiguration = new DnsConfiguration(); }
        else { retired.Dispose(); }

        // Exercise real resolver acquisition; synthetic query overrides bypass its disposed guard.
        using var lease = (IDisposable)typeof(DnsConfiguration)
            .GetMethod("AcquireResolver", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(survivor.DnsConfiguration, null)!;
        Assert.Same(survivor.DnsConfiguration, survivor.NSAnalysis.DnsConfiguration);
        Assert.Equal("SyntheticSnapshotAgent", survivor.DnsConfiguration.UserAgent);
        Assert.Equal(3, survivor.DnsConfiguration.ResolverMaxConcurrency);
        Assert.Equal(TimeSpan.FromSeconds(37), survivor.DnsConfiguration.MaxCacheTtl);
        Assert.Equal(new[] { DnsEndpoint.Cloudflare }, survivor.DnsConfiguration.DnsEndpoints);
        Assert.True(survivor.DnsConfiguration.EnableResponseCache);
        Assert.NotSame(source.DnsConfiguration, snapshot.DnsConfiguration);
        Assert.NotSame(source.DnsConfiguration.DnsEndpoints, snapshot.DnsConfiguration.DnsEndpoints);
    }
}
