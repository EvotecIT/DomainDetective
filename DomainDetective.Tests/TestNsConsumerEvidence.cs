using DnsClientX;
using DomainDetective.DesiredState;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestNsConsumerEvidence {
    [Fact]
    public async Task PublicOverviewsPreserveUnknownNsPresence() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await health.VerifyNS("example.com");
        var domain = Converters.ConvertDomainOverview(health, "example.com").MailDnsChecks.Single(item => item.Key == "ns");
        var tenant = Converters.ConvertMicrosoft365Overview(health, "example.com").MailDnsChecks.Single(item => item.Key == "ns");
        Assert.All(new[] { domain, tenant }, item => {
            Assert.Equal(AggregateCheckState.Unknown, item.State);
            Assert.Equal("Unknown", item.Value);
            Assert.DoesNotContain("No authoritative nameservers", item.Detail);
        });
    }

    [Fact]
    public async Task DesiredStateRequiresEvidenceWithoutInventingMissingNsOrGlue() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) => Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await health.VerifyNS("example.com");
        var profile = new DesiredStateProfile {
            Ns = new DesiredStateNsPolicy { RequireRecord = true },
            Delegation = new DesiredStateDelegationPolicy { RequireMatchesParent = true, RequireGlueComplete = true, RequireGlueConsistent = true }
        };
        var result = DesiredStateEvaluator.Evaluate("example.com", health, profile);
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, item => item.Code == "DesiredState.NS.Evidence.Incomplete");
        Assert.Contains(result.Assessments, item => item.Code == "DesiredState.Delegation.Evidence.Incomplete");
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.NsMissingRecord
            || item.Code == DesiredStateCodes.DelegationMismatch || item.Code == DesiredStateCodes.DelegationGlueIncomplete
            || item.Code == DesiredStateCodes.DelegationGlueInconsistent);
    }

    [Fact]
    public async Task FilteredNsEvidenceRemainsIndependentAcrossBothRefreshDirections() {
        using var health = CreateHealth();
        bool failed = true;
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(failed
            ? new DnsResponse { Status = DnsResponseCode.ServerFailure }
            : new DnsResponse { Status = DnsResponseCode.NoError, Answers = type == DnsRecordType.NS
                ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns1.example.test" } } : Array.Empty<DnsAnswer>() });
        await health.VerifyNS("example.com");
        using var filtered = health.FilterAnalyses(new[] { HealthCheckType.NS });
        var savedErrors = filtered.NSAnalysis.DnsQueryErrors.ToArray();
        failed = false;
        await health.VerifyNS("example.com");
        Assert.Equal(savedErrors, filtered.NSAnalysis.DnsQueryErrors);
        Assert.True(filtered.NSAnalysis.DnsQueryFailed);
        Assert.Contains(filtered.NSAnalysis.Assessments, item => item.Code == NSCodes.QueryFailed);
        failed = true;
        await filtered.VerifyNS("example.com");
        Assert.False(health.NSAnalysis.DnsQueryFailed);
        Assert.True(health.NSAnalysis.NsLookupComplete);
        Assert.DoesNotContain(health.NSAnalysis.Assessments, item => item.Code == NSCodes.QueryFailed);
    }

    [Fact]
    public async Task DefaultDelegationObservesParentAuthorityRatherThanRecursiveChildAnswer() {
        using var health = CreateHealth();
        ConfigureParentDiscovery(health);
        int directCalls = 0;
        health.NSAnalysis.QueryResponseOverride = (address, query, _) => {
            Interlocked.Increment(ref directCalls);
            Assert.Equal("192.0.2.53", address.ToString());
            Assert.Equal("example.com", query.Name.TrimEnd('.'));
            Assert.Equal(0, query.SerializeDnsWireFormat()[2] & 1);
            return Task.FromResult<DnsResponse?>(new DnsResponse { Status = DnsResponseCode.NoError,
                Authorities = new[] { new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, DataRaw = "parent-observed.example.test" } } });
        };
        await health.VerifyDelegation("example.com");
        Assert.True(directCalls > 0);
        Assert.Equal(new[] { "child.example.test" }, health.NSAnalysis.NsRecords);
        Assert.Equal(new[] { "parent-observed.example.test" }, health.NSAnalysis.ParentNsRecords);
        Assert.False(health.NSAnalysis.DelegationMatches);
        Assert.True(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Equal("192.0.2.53", health.NSAnalysis.ParentAuthorityServer);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ChildAnswersFromSharedParentServerCannotCertifyDelegation(bool authoritative) {
        using var health = CreateHealth();
        ConfigureParentDiscovery(health);
        health.NSAnalysis.QueryResponseOverride = (_, query, _) => Task.FromResult<DnsResponse?>(new DnsResponse {
            Status = DnsResponseCode.NoError, IsAuthoritativeAnswer = authoritative,
            Answers = new[] { new DnsAnswer { Name = query.Name, Type = DnsRecordType.NS, DataRaw = "child.example.test" } }
        });
        await health.VerifyDelegation("sub.example.com");
        Assert.True(health.NSAnalysis.NsLookupComplete);
        Assert.Equal(new[] { "child.example.test" }, health.NSAnalysis.NsRecords);
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Empty(health.NSAnalysis.ParentNsRecords);
        Assert.False(health.NSAnalysis.DelegationMatches);
        Assert.True(health.NSAnalysis.DnsQueryFailed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ParentProbeDeadlineAndCallerCancellationObserveOwnedTransport(bool cancelCaller) {
        using var health = CreateHealth();
        ConfigureParentDiscovery(health);
        using var caller = new CancellationTokenSource();
        health.NSAnalysis.ParentDelegationTimeout = TimeSpan.FromMilliseconds(cancelCaller ? 5000 : 100);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        bool exited = false;
        health.NSAnalysis.QueryResponseOverride = async (_, _, token) => {
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); return null; }
            finally { exited = true; }
        };
        var operation = health.VerifyDelegation("example.com", caller.Token);
        await entered.Task;
        if (cancelCaller) {
            caller.Cancel();
            var cancellation = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
            Assert.Equal(caller.Token, cancellation.CancellationToken);
        } else {
            await operation;
            Assert.True(health.NSAnalysis.DnsQueryFailed);
        }
        Assert.True(exited);
        Assert.True(health.NSAnalysis.NsLookupComplete);
        Assert.False(health.NSAnalysis.DelegationAnalysisComplete);
        Assert.Empty(health.NSAnalysis.ParentNsRecords);
    }

    [Fact]
    public async Task DesiredStateRetainsConfirmedMissingGlueWithoutInventingInconsistency() {
        using var health = CreateHealth();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse {
            Answers = type == DnsRecordType.NS ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns1.example.com" } }
                : Array.Empty<DnsAnswer>()
        });
        health.NSAnalysis.QueryDnsFullOverride = (name, type) => Task.FromResult<IEnumerable<DnsResponse>>(new[] {
            new DnsResponse { Authorities = new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns1.example.com" } } }
        });
        await health.VerifyDelegation("example.com");
        var result = DesiredStateEvaluator.Evaluate("example.com", health, new DesiredStateProfile {
            Delegation = new DesiredStateDelegationPolicy { RequireGlueComplete = true, RequireGlueConsistent = true }
        });
        Assert.False(result.Conforms);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.DelegationGlueIncomplete);
        Assert.Contains(result.Assessments, item => item.Code == DesiredStateCodes.DelegationEvidenceIncomplete);
        Assert.DoesNotContain(result.Assessments, item => item.Code == DesiredStateCodes.DelegationGlueInconsistent);
    }

    private static void ConfigureParentDiscovery(DomainHealthCheck health) {
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse {
            Status = DnsResponseCode.NoError,
            Answers = type == DnsRecordType.SOA ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "ns.parent.test hostmaster.parent.test 1 2 3 4 5" } }
                : type == DnsRecordType.NS ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = name == "com" ? "ns.parent.test" : "child.example.test" } }
                : type == DnsRecordType.A ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "192.0.2.53" } } : Array.Empty<DnsAnswer>()
        });
    }

    private static DomainHealthCheck CreateHealth() {
        var health = new DomainHealthCheck();
        health.NSAnalysis.EnableChaosFingerprinting = false;
        health.NSAnalysis.LookupAsnOverride = _ => Task.FromResult<int?>(null);
        return health;
    }
}
