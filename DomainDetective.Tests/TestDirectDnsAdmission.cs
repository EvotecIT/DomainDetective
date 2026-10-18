using DnsClientX;
using DomainDetective.Helpers;

namespace DomainDetective.Tests;

public class TestDirectDnsAdmission {
    [Theory]
    [InlineData(null)]
    [InlineData(2)]
    public async Task CombinedScanKeepsOwnerBoundsUnlessSharedDnsCapIsExplicit(int? configuredLimit) {
        using var health = new DomainHealthCheck();
        health.ExecutionOptions.DnsParallelism = configuredLimit;
        bool observed = false;
        int? directCapacity = null;
        health.DnsConfiguration.QueryDnsResponseOverride = (owner, type, token) => {
            observed = true;
            directCapacity = ScanObservations.Current!.DirectDnsAdmission?.CurrentCount;
            return Task.FromResult(new DnsResponse {
                Status = DnsResponseCode.NoError,
                Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "0 issue ca.example" } }
            });
        };
        await health.Verify("admission.example", new[] { HealthCheckType.CAA });
        Assert.True(observed);
        Assert.Equal(configuredLimit, directCapacity);
    }

    [Fact]
    public async Task WaitingForDirectAdmissionDoesNotConsumeTheWireTimeout() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var observations = new ScanObservations(1);
        var admission = observations.DirectDnsAdmission!;
        await admission.WaitAsync(guard.Token);
        bool held = true;
        // Invalid address keeps this focused on admission: after admission the
        // transport returns unavailable without sending a network packet.
        var query = AuthoritativeDnsProbes.QueryAsync("invalid-address", "held.example", DnsRecordType.A,
            timeoutMs: 50, cancellationToken: guard.Token);
        try {
            Task heldLongerThanWireBudget = Task.Delay(200, guard.Token);
            Assert.Same(heldLongerThanWireBudget, await Task.WhenAny(query, heldLongerThanWireBudget));
            Assert.False(query.IsCompleted);
            admission.Release();
            held = false;
            Assert.Null(await query.WaitWithCancellation(guard.Token));
            Assert.Equal(1, admission.CurrentCount);
        } finally {
            if (held) { admission.Release(); }
            try { await query; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task CallerCanCancelQueuedDirectProbeWithoutReleasingAnotherOwnersSlot() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var caller = new CancellationTokenSource();
        using var observations = new ScanObservations(1);
        var admission = observations.DirectDnsAdmission!;
        await admission.WaitAsync(guard.Token);
        try {
            Task query = AuthoritativeDnsProbes.QueryAsync("invalid-address", "cancel.example", DnsRecordType.A,
                cancellationToken: caller.Token);
            caller.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.WaitWithCancellation(guard.Token));
            Assert.Equal(caller.Token, error.CancellationToken);
            Assert.Equal(0, admission.CurrentCount);
        } finally { admission.Release(); }
        Assert.Equal(1, admission.CurrentCount);
    }
}
