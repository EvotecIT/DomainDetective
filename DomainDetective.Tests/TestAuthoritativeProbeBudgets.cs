using DnsClientX;
using DomainDetective.Helpers;
using System.Net;

namespace DomainDetective.Tests;

public class TestAuthoritativeProbeBudgets {
    [Fact]
    public async Task SlowMxAliasLookupRetainsAddressEvidenceAndReportsUnknownAliasStatus() {
        using var health = new DomainHealthCheck();
        var analysis = health.MXAnalysis;
        analysis.Subject = "example.test";
        analysis.QueryDnsOverride = async (name, type) => {
            if (type == DnsRecordType.CNAME) {
                await Task.Delay(3000);
                return new[] { new DnsAnswer { Type = type, DataRaw = "alias.example.test" } };
            }
            return type == DnsRecordType.A ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } } : Array.Empty<DnsAnswer>();
        };
        await analysis.AnalyzeMxRecords(new[] { new DnsAnswer { Type = DnsRecordType.MX, DataRaw = "0 mail.example.test" } }, new InternalLogger());
        Assert.True(analysis.CnameQueryFailed);
        Assert.False(analysis.PointsToCname);
        Assert.False(analysis.PointsToNonExistentDomain);
        Assert.True(DomainDetective.Views.Converters.Convert(analysis).CnameQueryFailed);
        Assert.False(analysis.ValidMxConfiguration);
        Assert.False(analysis.ValidateMxConfiguration());
        Assert.Contains(analysis.Assessments, a => a.Code == "MX.Cname.QueryFailed");
        var desired = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile {
                Mx = new DomainDetective.DesiredState.DesiredStateMxPolicy { DisallowCnameTargets = true }
            });
        Assert.False(desired.Conforms);
        Assert.Contains(desired.Assessments, a => a.Code == "DesiredState.MX.Cname.QueryFailed");
    }
    [Fact]
    public async Task ValidatedQueryBudgetRetainsUnknownRatherThanClaimingAbsentRecords() {
        using var configuration = new DnsConfiguration { DnsSecQueryTimeout = TimeSpan.FromMilliseconds(50) };
        configuration.QueryDnsResponseOverride = async (_, _, token) => {
            await Task.Delay(Timeout.Infinite, token);
            return new DnsResponse();
        };
        var response = await DnsSecAnalysis.QueryValidatedSubjectResponseAsync("_443._tcp.example.test", DnsRecordType.TLSA, configuration, default);
        Assert.Equal(DnsResponseCode.ServerFailure, response.Status);
        Assert.Contains("budget exhausted", response.Error);
        Assert.Empty(response.Answers);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsSecAnalysis.QueryValidatedSubjectResponseAsync("_443._tcp.example.test", DnsRecordType.TLSA, configuration, canceled.Token));
    }

    [Fact]
    public async Task NameServerEnrichmentRunsConcurrentlyAndRetainsEveryAnswer() {
        var admitted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int started = 0;
        var analysis = new NSAnalysis { Subject = "example.test", EnableChaosFingerprinting = false,
            QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.A
                ? new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }, new DnsAnswer { Type = type, DataRaw = "192.0.2.2" } }
                : Array.Empty<DnsAnswer>()),
            LookupAsnOverride = async address => {
                if (Interlocked.Increment(ref started) == 2) { admitted.TrySetResult(true); }
                await release.Task;
                return address.EndsWith("1", StringComparison.Ordinal) ? 64512 : 64513;
            } };
        var run = analysis.AnalyzeNsRecords(new[] { new DnsAnswer { Type = DnsRecordType.NS, DataRaw = "ns.example.test" } }, new InternalLogger());
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await admitted.Task.WaitWithCancellation(guard.Token); }
        finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(2, analysis.AsnByIp.Count);
        Assert.Equal(2, analysis.AsnDistinctCount);
    }

    [Fact]
    public void Ipv6ReachabilityNoteRequiresIpv4EvidenceAndNoIpv6Replies() {
        var logger = new InternalLogger();
        var analysis = new NSAnalysis();
        using var collector = AssessmentCollector.ForAnalysis(logger, analysis);
        var addresses = new[] { "192.0.2.1", "2001:db8::1" };
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, new[] { "192.0.2.1" }, logger);
        var note = Assert.Single(analysis.Assessments);
        Assert.Equal("DNS.Authoritative.IPv6.NoUsableResponse", note.Code);
        Assert.Equal(AssessmentSeverity.Info, note.Severity);
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, Array.Empty<string>(), logger);
        AuthoritativeDnsProbes.ReportIpv6Reachability(addresses, addresses, logger);
        Assert.Single(analysis.Assessments);
    }
}
