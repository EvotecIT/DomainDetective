using Xunit;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateMonitor {
        [Fact]
        public async Task ProducesSummaryCounts() {
            var monitor = new CertificateMonitor {
                AnalysisOverride = (url, _, _, _) => Task.FromResult(new CertificateAnalysis {
                    IsReachable = url.Contains("good.example.test", StringComparison.Ordinal),
                    IsValid = url.Contains("good.example.test", StringComparison.Ordinal)
                })
            };
            await monitor.Analyze(new[] { "https://good.example.test", "https://unreachable.example.test" }, showProgress: false);

            Assert.Equal(2, monitor.Results.Count);
            Assert.Equal(1, monitor.ValidCount);
            Assert.Equal(1, monitor.FailedCount);

            var reachable = monitor.Results.Find(r => r.Analysis.IsReachable);
            Assert.NotNull(reachable);
            Assert.Equal("good.example.test", reachable!.ResolvedHost);
            Assert.False(monitor.Results.Find(r => r.Host == "https://unreachable.example.test")!.Analysis.IsReachable);
        }

        [Fact]
        public void TimerStopsAfterDispose() {
            var monitor = new CertificateMonitor();
            monitor.Start(Array.Empty<string>(), TimeSpan.FromMilliseconds(10));
            Assert.True(monitor.IsRunning);
            monitor.Dispose();
            Assert.False(monitor.IsRunning);
        }

        [Fact]
        public async Task CanStartAndStopMultipleTimes() {
            var monitor = new CertificateMonitor();
            for (int i = 0; i < 3; i++) {
                monitor.Start(Array.Empty<string>(), TimeSpan.FromMilliseconds(1));
                Assert.True(monitor.IsRunning);
                await monitor.StopAsync();
                Assert.False(monitor.IsRunning);
            }
        }

        [Fact]
        public async Task AnalyzeCancellationWaitsForInFlightTasks() {
            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var completed = 0;
            var invocationCount = 0;
            using var cts = new CancellationTokenSource();

            var monitor = new CertificateMonitor {
                MaxParallelism = 1,
                AnalysisOverride = async (_, _, _, cancellationToken) => {
                    if (Interlocked.Increment(ref invocationCount) == 1) {
                        started.TrySetResult(true);
                        await release.Task;
                        Volatile.Write(ref completed, 1);
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    return new CertificateAnalysis();
                }
            };

            var analyzeTask = monitor.Analyze(new[] { "https://a.example.test", "https://b.example.test" }, 443, cancellationToken: cts.Token, showProgress: false);
            await started.Task;
            cts.Cancel();
            release.TrySetResult(true);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analyzeTask);
            Assert.Equal(1, Volatile.Read(ref completed));
            Assert.True(invocationCount >= 1);
        }
    }
}
