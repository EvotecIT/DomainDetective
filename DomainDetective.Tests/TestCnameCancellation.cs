using DnsClientX;

namespace DomainDetective.Tests;

public class TestCnameCancellation {
    [Theory]
    [InlineData(true, DnsRecordType.CNAME)]
    [InlineData(false, DnsRecordType.CNAME)]
    [InlineData(false, DnsRecordType.A)]
    public async Task OperationalDnsResponseDoesNotEstablishCnameAbsence(bool takeover, DnsRecordType failedType) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = type == failedType ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = type == DnsRecordType.CNAME && type != failedType
                ? new[] { new DnsAnswer { Type = type, DataRaw = "target.fixture.example" } } : Array.Empty<DnsAnswer>()
        });
        if (takeover) {
            await Assert.ThrowsAsync<DnsQueryFailureException>(() => health.VerifyTakeoverCname("fixture.example"));
        } else {
            await health.VerifyDanglingCname("fixture.example");
            Assert.False(string.IsNullOrEmpty(health.DanglingCnameAnalysis.FailureReason));
            Assert.False(health.DanglingCnameAnalysis.IsDangling);
        }
    }

    [Fact]
    public async Task AddressLookupFailureDoesNotEstablishADanglingTarget() {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => type == DnsRecordType.CNAME
            ? Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "fixture.azurewebsites.net" } })
            : throw new InvalidOperationException("Synthetic address lookup failure");
        await health.VerifyDanglingCname("fixture.example");
        Assert.True(health.DanglingCnameAnalysis.CnameRecordExists);
        Assert.Contains("Synthetic address lookup failure", health.DanglingCnameAnalysis.FailureReason);
        Assert.False(health.DanglingCnameAnalysis.IsDangling);
        Assert.False(health.DanglingCnameAnalysis.UnclaimedService);
    }

    [Theory]
    [InlineData(true, DnsRecordType.CNAME)]
    [InlineData(false, DnsRecordType.CNAME)]
    [InlineData(false, DnsRecordType.A)]
    [InlineData(false, DnsRecordType.AAAA)]
    public async Task CallerCancellationReachesEachCnameResolutionPhase(bool takeover, DnsRecordType blockedType) {
        using var health = new DomainHealthCheck();
        using var caller = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, type, token) => {
            if (type == blockedType) {
                Interlocked.Increment(ref active);
                entered.TrySetResult(true);
                try { await Task.Delay(Timeout.Infinite, token); }
                finally { Interlocked.Decrement(ref active); }
            }
            return new DnsResponse { Status = DnsResponseCode.NoError, Answers = type == DnsRecordType.CNAME
                ? new[] { new DnsAnswer { Type = type, DataRaw = "target.fixture.example" } } : Array.Empty<DnsAnswer>() };
        };
        var run = takeover ? health.VerifyTakeoverCname("fixture.example", caller.Token)
            : health.VerifyDanglingCname("fixture.example", caller.Token);
        await entered.Task.WaitWithCancellation(guard.Token);
        caller.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitWithCancellation(guard.Token));
        Assert.Equal(caller.Token, error.CancellationToken);
        Assert.Equal(0, active);
    }
}
