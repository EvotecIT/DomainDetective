using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestHealthBatchLifetime {
    [Fact]
    public async Task InputEnumerationIsBoundedByAdmittedDomains() {
        int created = 0;
        IEnumerable<string> Domains() {
            for (int index = 0; index < 12; index++) {
                if (index - Volatile.Read(ref created) >= 3) {
                    throw new InvalidOperationException("Input was consumed before bounded admission.");
                }
                yield return "d" + index + ".example.com";
            }
        }
        var runs = await DomainHealthCheck.VerifyBatchAsync(Domains(), new[] { HealthCheckType.DMARC },
            executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 3 },
            healthCheckFactory: _ => {
                Interlocked.Increment(ref created);
                var health = new DomainHealthCheck();
                health.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(new[] {
                    new DnsAnswer { Type = DnsRecordType.TXT, DataRaw = "v=DMARC1; p=reject" }
                });
                return health;
            });
        try {
            Assert.Equal(12, runs.Count);
            for (int index = 0; index < runs.Count; index++) {
                Assert.Equal("d" + index + ".example.com", runs[index].DomainName);
                Assert.True(runs[index].Success, runs[index].Error?.Message);
            }
        } finally {
            foreach (var run in runs) { run.HealthCheck?.Dispose(); }
        }
    }
    [Fact]
    public async Task ResultDisposesDefaultOwnedHealthCheck() {
        var runs = await DomainHealthCheck.VerifyBatchAsync(new[] { "example.com" }, new[] { HealthCheckType.ARC });
        var run = Assert.Single(runs);
        Assert.True(run.OwnsHealthCheck);
        Assert.NotNull(run.Error);
        run.Dispose(); run.Dispose();
        AssertDisposed(run.HealthCheck!);
    }

    [Fact]
    public async Task FactoryFailureIsReportedAndBorrowedInstancesRemainCallerOwned() {
        using var borrowed = new DomainHealthCheck();
        var runs = await DomainHealthCheck.VerifyBatchAsync(new[] { "bad.example", "good.example" },
            new[] { HealthCheckType.ARC }, healthCheckFactory: domain =>
                domain.StartsWith("bad", StringComparison.Ordinal) ? throw new InvalidOperationException("factory failed") : borrowed);
        Assert.Equal("factory failed", runs[0].Error!.Message);
        Assert.Null(runs[0].HealthCheck);
        Assert.Same(borrowed, runs[1].HealthCheck);
        Assert.False(runs[1].OwnsHealthCheck);
        runs[1].Dispose();
        using var lease = Acquire(borrowed);
    }

    [Fact]
    public async Task CancellationDrainsAdmittedChecksAndPreservesBorrowedInstances() {
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var instances = new System.Collections.Concurrent.ConcurrentBag<DomainHealthCheck>();
        int started = 0, finished = 0;
        Task<IReadOnlyList<DomainHealthCheckRun>> batch = DomainHealthCheck.VerifyBatchAsync(
            Enumerable.Range(0, 12).Select(index => "d" + index + ".example.com"), new[] { HealthCheckType.DMARC },
            executionOptions: new HealthCheckExecutionOptions { MaxDomainParallelism = 2 }, healthCheckFactory: _ => {
                var health = new DomainHealthCheck();
                instances.Add(health);
                health.DnsConfiguration.QueryDnsResponseOverride = async (_, _, token) => {
                    if (Interlocked.Increment(ref started) == 2) { entered.TrySetResult(true); }
                    try { await Task.Delay(Timeout.Infinite, token); }
                    finally { Interlocked.Increment(ref finished); }
                    return new DnsResponse();
                };
                return health;
            }, cancellationToken: cancellation.Token);
        try {
            Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000)));
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => batch);
            Assert.Equal(2, started);
            Assert.Equal(started, finished);
            foreach (var instance in instances) { using var lease = Acquire(instance); }
        } finally {
            cancellation.Cancel();
            try { await batch; } catch (OperationCanceledException) { }
            foreach (var instance in instances) { instance.Dispose(); }
        }
    }

    private static IDisposable Acquire(DomainHealthCheck health) => (IDisposable)typeof(DnsConfiguration)
        .GetMethod("AcquireResolver", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(health.DnsConfiguration, null)!;

    private static void AssertDisposed(DomainHealthCheck health) {
        var error = Assert.Throws<TargetInvocationException>(() => Acquire(health));
        Assert.IsType<ObjectDisposedException>(error.InnerException);
    }

}
