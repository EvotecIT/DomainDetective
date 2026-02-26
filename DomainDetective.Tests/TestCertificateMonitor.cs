using Xunit;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateMonitor {
        [Fact]
        public async Task ProducesSummaryCounts() {
            var monitor = new CertificateMonitor();
            await monitor.Analyze(new[] { "https://www.google.com", "https://nonexistent.invalid" });
            if (monitor.Results.TrueForAll(r => !r.Analysis.IsReachable)) {
                return;
            }
            Assert.Equal(2, monitor.Results.Count);
            Assert.True(monitor.ValidCount >= 1);
            Assert.True(monitor.FailedCount >= 1);

            var reachable = monitor.Results.Find(r => r.Analysis.IsReachable);
            Assert.NotNull(reachable);
            Assert.Equal(reachable!.Analysis.TlsProtocol, reachable.Protocol);
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
            var timerField = typeof(CertificateMonitor).GetField("_timer", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
            for (int i = 0; i < 3; i++) {
                monitor.Start(Array.Empty<string>(), TimeSpan.FromMilliseconds(1));
                Assert.NotNull(timerField.GetValue(monitor));
                await monitor.StopAsync();
                Assert.Null(timerField.GetValue(monitor));
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
