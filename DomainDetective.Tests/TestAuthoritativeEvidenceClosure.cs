using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestAuthoritativeEvidenceClosure {
    [Fact]
    public async Task AliasBatchRespectsASingleResolverSlotAndRetainsAllAnswers() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.ResolverMaxConcurrency = 1;
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0, maximum = 0, completed = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            if (type != DnsRecordType.CNAME) {
                return new DnsResponse { Answers = type == DnsRecordType.A
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>() };
            }
            int count = Interlocked.Increment(ref active);
            maximum = Math.Max(maximum, count);
            try {
                await release.Task.WaitWithCancellation(token);
                Interlocked.Increment(ref completed);
                return new DnsResponse { Answers = new[] { new DnsAnswer { Type = type, DataRaw = "alias.example.test" } } };
            } finally { Interlocked.Decrement(ref active); }
        };
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        var run = analysis.AnalyzeMxRecords(Enumerable.Range(1, 3).Select(index =>
            new DnsAnswer { Type = DnsRecordType.MX, DataRaw = $"{index * 10} mail{index}.example.test" }), new InternalLogger());
        try { Assert.Equal(1, Volatile.Read(ref active)); }
        finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(1, maximum);
        Assert.Equal(3, completed);
        Assert.True(analysis.PointsToCname);
        Assert.False(analysis.CnameQueryFailed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MixedRecordPresenceIsReportedAsNonUniform(bool allAbsent) {
        var analysis = new DnsTtlAnalysis();
        analysis.ServerTtlA["192.0.2.1"] = allAbsent ? null : 3600;
        analysis.ServerTtlA["192.0.2.2"] = null;
        var logger = new InternalLogger();
        using var collector = AssessmentCollector.ForAnalysis(logger, analysis, category: "TTL", target: "example.test");
        analysis.EvaluateUniformity(Array.Empty<string>(), logger);
        Assert.False(analysis.AUniformAcrossServers);
        Assert.False(analysis.UniformityIncomplete);
        Assert.Equal(!allAbsent, analysis.Assessments.Any(item => item.Code == TtlCodes.NonUniformAcrossNS_A));
        Assert.Equal(!allAbsent, Converters.Convert(analysis).WarningCount > 0);
    }

    [Theory]
    [InlineData("not an IP address", "example.test")]
    [InlineData("192.0.2.1", "invalid..example.test")]
    public async Task MalformedWireProbeInputsBecomeUnavailableEvidence(string address, string owner) {
        var response = await AuthoritativeDnsProbes.QueryAsync(address, owner, DnsRecordType.A, timeoutMs: 25);
        Assert.Null(response);
    }
}
