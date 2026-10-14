using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestHealthBatchProcessing {
    [Fact]
    public async Task ProcessingHoldsAdmissionSlotsUntilConsumersFinish() {
        int enumerated = 0, processed = 0, entered = 0;
        var consumersEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var instances = new ConcurrentBag<DomainHealthCheck>();
        IEnumerable<string> Domains() {
            for (int index = 0; index < 6; index++) {
                if (Volatile.Read(ref enumerated) - Volatile.Read(ref processed) >= 2) {
                    throw new InvalidOperationException("Admission bypassed the active consumers.");
                }
                Interlocked.Increment(ref enumerated);
                yield return "d" + index + ".example.com";
            }
        }
        Task processing = DomainHealthCheck.ProcessBatchAsync(Domains(), async (run, token) => {
            Assert.False(run.OwnsHealthCheck);
            Assert.True(run.Success, run.Error?.Message);
            Assert.True(token.CanBeCanceled);
            if (Interlocked.Increment(ref entered) == 2) { consumersEntered.TrySetResult(true); }
            await release.Task;
            run.HealthCheck!.Dispose();
            Interlocked.Increment(ref processed);
        }, new[] { HealthCheckType.DMARC },
            executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 2 },
            healthCheckFactory: _ => {
                var health = SuccessfulHealth(); instances.Add(health); return health;
            });
        try {
            Assert.Same(consumersEntered.Task, await Task.WhenAny(consumersEntered.Task, Task.Delay(30000)));
            Assert.Equal(2, enumerated); Assert.Equal(0, processed);
            release.TrySetResult(true);
            await processing;
            Assert.Equal(6, processed); Assert.Equal(6, enumerated);
            foreach (var health in instances) { AssertDisposed(health); }
        } finally {
            release.TrySetResult(true);
            await processing;
            foreach (var health in instances) { health.Dispose(); }
        }
    }

    [Fact]
    public async Task CallbackFailureDrainsActiveChecksAndPreservesItsErrorOverEnumeratorDisposal() {
        int entered = 0, finished = 0;
        var bothEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var instances = new ConcurrentBag<DomainHealthCheck>();
        IEnumerable<string> Domains() {
            try {
                yield return "first.example.com";
                yield return "held.example.com";
            } finally { throw new IOException("enumerator disposal failed"); }
        }
        try {
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => DomainHealthCheck.ProcessBatchAsync(
                Domains(), (_, _) => throw new InvalidOperationException("consumer failed"),
                new[] { HealthCheckType.DMARC },
                executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 2 },
                healthCheckFactory: domain => {
                    var health = new DomainHealthCheck(); instances.Add(health);
                    health.DnsConfiguration.QueryDnsResponseOverride = async (name, _, token) => {
                        if (Interlocked.Increment(ref entered) == 2) { bothEntered.TrySetResult(true); }
                        try {
                            await bothEntered.Task;
                            if (domain.StartsWith("held", StringComparison.Ordinal)) { await Task.Delay(Timeout.Infinite, token); }
                            return Response(name);
                        } finally { Interlocked.Increment(ref finished); }
                    };
                    return health;
                }));
            Assert.Equal("consumer failed", error.Message);
            Assert.Equal(2, entered); Assert.Equal(2, finished);
            foreach (var health in instances) { using var lease = Acquire(health); }
        } finally { foreach (var health in instances) { health.Dispose(); } }
    }

    [Fact]
    public async Task ProcessingReleasesLibraryOwnedHealthAfterFailureResultIsConsumed() {
        DomainHealthCheck? observed = null;
        await DomainHealthCheck.ProcessBatchAsync(new[] { "example.com" }, (run, _) => {
            Assert.True(run.OwnsHealthCheck);
            Assert.NotNull(run.Error);
            observed = run.HealthCheck;
            using var lease = Acquire(observed!);
            return Task.CompletedTask;
        }, new[] { HealthCheckType.ARC });
        Assert.NotNull(observed);
        AssertDisposed(observed!);
    }

    [Fact]
    public async Task CallerCancellationDrainsConsumerAndPreservesBorrowedHealth() {
        using var caller = new CancellationTokenSource();
        using var health = SuccessfulHealth();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int finished = 0;
        Task processing = DomainHealthCheck.ProcessBatchAsync(new[] { "example.com" }, async (_, token) => {
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Increment(ref finished); }
        }, new[] { HealthCheckType.DMARC }, healthCheckFactory: _ => health, cancellationToken: caller.Token);
        try {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(30000)));
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processing);
            Assert.Equal(1, finished);
            using var lease = Acquire(health);
        } finally {
            caller.Cancel();
            try { await processing; } catch (OperationCanceledException) { }
        }
    }

    private static DomainHealthCheck SuccessfulHealth() {
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, _, _) => Task.FromResult(Response(name));
        return health;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerCancellationSurvivesInputDisposalFailure(bool processingRoute) {
        using var caller = new CancellationTokenSource();
        using var health = new DomainHealthCheck();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int finished = 0;
        health.DnsConfiguration.QueryDnsResponseOverride = async (_, _, token) => {
            entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); }
            finally { Interlocked.Increment(ref finished); }
            return new DnsResponse();
        };
        IEnumerable<string> Domains() {
            try { yield return "example.com"; }
            finally { throw new IOException("input disposal failed"); }
        }
        Task batch = processingRoute
            ? DomainHealthCheck.ProcessBatchAsync(Domains(), (_, _) => Task.CompletedTask,
                new[] { HealthCheckType.DMARC },
                executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 1 },
                healthCheckFactory: _ => health, cancellationToken: caller.Token)
            : DomainHealthCheck.VerifyBatchAsync(Domains(), new[] { HealthCheckType.DMARC },
                executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 1 },
                healthCheckFactory: _ => health, cancellationToken: caller.Token);
        try {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(30000)));
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => batch);
            Assert.Equal(1, finished);
            using var lease = Acquire(health);
        } finally {
            caller.Cancel();
            try { await batch; } catch (OperationCanceledException) { }
        }
    }

    private static DnsResponse Response(string name) => new() {
        Status = DnsResponseCode.NoError,
        Answers = new[] { new DnsAnswer { Name = name, Type = DnsRecordType.TXT, DataRaw = "v=DMARC1; p=reject" } }
    };

    private static IDisposable Acquire(DomainHealthCheck health) => (IDisposable)typeof(DnsConfiguration)
        .GetMethod("AcquireResolver", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(health.DnsConfiguration, null)!;

    private static void AssertDisposed(DomainHealthCheck health) {
        var error = Assert.Throws<TargetInvocationException>(() => Acquire(health));
        Assert.IsType<ObjectDisposedException>(error.InnerException);
    }
}
