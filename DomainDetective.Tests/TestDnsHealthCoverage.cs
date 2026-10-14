using System;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.Narratives;
using DomainDetective.DesiredState;
using DomainDetective.Definitions;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsHealthCoverage {
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task AddressDiscoveryFailureCannotProduceCompleteIpv4Consistency(int failureKind) {
        var health = new DomainHealthCheck();
        var analysis = health.DnsHealthAnalysis;
        analysis.DnsConfiguration = CreateAnalysis().DnsConfiguration;
        var answers = analysis.DnsConfiguration.QueryDnsOverride!;
        analysis.DnsConfiguration.QueryDnsOverride = null;
        analysis.DnsConfiguration.QueryDnsResponseOverride = async (name, type, _) => {
            if (type == DnsRecordType.AAAA) {
                if (failureKind == 0) throw new TimeoutException("Address discovery timed out.");
                return new DnsResponse {
                    Status = failureKind == 1 ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
                    Answers = Array.Empty<DnsAnswer>()
                };
            }
            return new DnsResponse { Status = DnsResponseCode.NoError, Answers = await answers(name, type) };
        };
        analysis.QueryResponseOverride = (_, query, _) => Task.FromResult<DnsResponse?>(Response(query.Type));
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Equal(6, analysis.ProbeResults.Count);
        Assert.Equal(failureKind == 2, analysis.ServersResponsive);
        Assert.Equal(failureKind == 2, analysis.SoaSerialConsistent);
        Assert.Equal(failureKind == 2, analysis.ApexAddressesConsistent);
        if (failureKind != 2) {
            Assert.Contains(analysis.Assessments, item => item.Code == DnsHealthCodes.CoverageIncomplete);
            Assert.DoesNotContain(DnsHealthNarrative.Build(analysis).Highlights, text => text.Contains("did not respond"));
            var desired = DesiredStateEvaluator.Evaluate("example.com", health,
                new DesiredStateProfile { DnsHealth = new DesiredStateDnsHealthPolicy { RequireServersResponsive = true } },
                MailDomainClassificationCategory.SendingAndReceiving);
            var warning = Assert.Single(desired.Assessments, item => item.Code == DesiredStateCodes.DnsHealthServersUnresponsive);
            Assert.Contains("could not be confirmed", warning.Message);
        }
    }

    [Fact]
    public async Task FailedNameserverDiscoveryDoesNotClaimObservedServerNonresponse() {
        var analysis = CreateAnalysis();
        analysis.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("Discovery failed.");
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Empty(analysis.ProbeResults);
        Assert.Contains(analysis.Assessments, item => item.Code == DnsHealthCodes.CoverageIncomplete);
        Assert.DoesNotContain(DnsHealthNarrative.Build(analysis).Highlights, text => text.Contains("did not respond"));
    }

    [Fact]
    public async Task ProbeWorkersAreBoundedAndRetainEveryPlannedResult() {
        var analysis = CreateAnalysis();
        analysis.QueryConcurrency = 2;
        int active = 0, peak = 0, calls = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.QueryResponseOverride = async (_, query, token) => {
            int now = Interlocked.Increment(ref active);
            peak = Math.Max(peak, now);
            if (Interlocked.Increment(ref calls) == 2) entered.TrySetResult(true);
            try { await release.Task; token.ThrowIfCancellationRequested(); return Response(query.Type); }
            finally { Interlocked.Decrement(ref active); }
        };
        Task run = analysis.Analyze("example.com", new InternalLogger());
        try {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000)));
            Assert.Equal(2, active);
        } finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(2, peak);
        Assert.Equal(6, calls);
        Assert.Equal(6, analysis.ProbeResults.Count);
    }

    [Fact]
    public async Task PartialIpv6CoverageDoesNotTurnIpv4AgreementIntoCompleteConsistency() {
        var analysis = CreateAnalysis(includeIpv6: true);
        analysis.QueryResponseOverride = (address, query, _) => address.AddressFamily == AddressFamily.InterNetworkV6
            ? Task.FromException<DnsResponse?>(new TimeoutException("IPv6 probe timed out."))
            : Task.FromResult<DnsResponse?>(Response(query.Type));
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.False(analysis.ServersResponsive);
        Assert.Equal(2, analysis.SoaSerialByServer.Count);
        Assert.Equal(DnsHealthConsistencyStatus.InsufficientEvidence, analysis.SoaSerialConsistency);
        Assert.Equal(DnsHealthConsistencyStatus.InsufficientEvidence, analysis.ApexAddressesConsistency);
        Assert.Equal(9, analysis.ProbeResults.Count);
        Assert.Equal(3, analysis.ProbeResults.Count(probe => !probe.HasResponse));
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DnsHealthCodes.SoaSerialSkew);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InternalBudgetAndCallerCancellationHaveDifferentOutcomes(bool callerCancellation) {
        var analysis = CreateAnalysis();
        analysis.QueryConcurrency = 1;
        analysis.AnalysisTimeoutMilliseconds = callerCancellation ? 5000 : 100;
        int calls = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.QueryResponseOverride = async (_, _, token) => {
            Interlocked.Increment(ref calls);
            entered.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, token);
            return null;
        };
        using var caller = new CancellationTokenSource();
        Task run = analysis.Analyze("example.com", new InternalLogger(), caller.Token);
        Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000)));
        if (callerCancellation) {
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        } else {
            await run;
            Assert.Equal(1, calls);
            Assert.Equal(6, analysis.ProbeResults.Count);
            Assert.All(analysis.ProbeResults, probe => Assert.Equal("Analysis budget exhausted.", probe.Error));
            Assert.False(analysis.ServersResponsive);
        }
    }
    [Fact]
    public async Task UnansweredServersCannotProducePositiveConsistency() {
        var analysis = CreateAnalysis();
        analysis.QueryResponseOverride = (_, _, _) => Task.FromResult<DnsResponse?>(null);
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.False(analysis.SoaSerialConsistent);
        Assert.False(analysis.ApexAddressesConsistent);
        Assert.False(analysis.ServersResponsive);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == DnsHealthCodes.SoaSerialConsistent);
        Assert.DoesNotContain(DnsHealthNarrative.Build(analysis).Highlights, text => text.Contains("serial numbers match"));
    }

    [Fact]
    public async Task NoDataIsAResponseAndCanBeComparedAcrossServers() {
        var analysis = CreateAnalysis();
        analysis.QueryResponseOverride = (_, query, _) => Task.FromResult<DnsResponse?>(Response(query.Type));
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.True(analysis.ServersResponsive);
        Assert.True(analysis.SoaSerialConsistent);
        Assert.True(analysis.ApexAddressesConsistent);
        Assert.Equal(2, analysis.ApexAddressesByServer.Count);
        Assert.All(analysis.ApexAddressesByServer.Values, addresses => Assert.Empty(addresses));
    }

    [Fact]
    public async Task SharedNameserverAddressIsProbedOnlyOnce() {
        var analysis = CreateAnalysis(sharedAddress: true);
        int calls = 0;
        analysis.QueryResponseOverride = (_, query, _) => {
            Interlocked.Increment(ref calls);
            return Task.FromResult<DnsResponse?>(Response(query.Type));
        };
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.Equal(3, calls);
        Assert.True(analysis.ServersResponsive);
        Assert.False(analysis.SoaSerialConsistent); // One endpoint is insufficient comparison evidence.
    }

    private static DnsHealthAnalysis CreateAnalysis(bool sharedAddress = false, bool includeIpv6 = false) => new() {
        DnsConfiguration = new DnsConfiguration {
            QueryDnsOverride = (name, type) => Task.FromResult((name, type) switch {
                ("example.com", DnsRecordType.NS) => new[] {
                    new DnsAnswer { Type = type, DataRaw = "ns1.example.com" },
                    new DnsAnswer { Type = type, DataRaw = "ns2.example.com" }
                },
                ("ns1.example.com", DnsRecordType.A) => new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } },
                ("ns2.example.com", DnsRecordType.A) => new[] { new DnsAnswer { Type = type, DataRaw = sharedAddress ? "192.0.2.1" : "192.0.2.2" } },
                ("ns1.example.com", DnsRecordType.AAAA) when includeIpv6 => new[] { new DnsAnswer { Type = type, DataRaw = "2001:db8::1" } },
                _ => Array.Empty<DnsAnswer>()
            })
        }
    };

    private static DnsResponse Response(DnsRecordType type) => new() {
        Status = DnsResponseCode.NoError,
        IsAuthoritativeAnswer = true,
        Answers = type == DnsRecordType.SOA ? new[] { new DnsAnswer {
            Name = "example.com", Type = type, DataRaw = "ns1.example.com hostmaster.example.com 12345 7200 900 1209600 3600"
        } } : Array.Empty<DnsAnswer>()
    };
}
