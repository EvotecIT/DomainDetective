using Xunit;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateMonitor {
        [Fact]
        public async Task ProducesSummaryCounts() {
            var monitor = new CertificateMonitor();
            await monitor.Analyze(new[] { "https://www.google.com", "https://nonexistent.invalid" });
            Assert.Equal(2, monitor.Results.Count);
            Assert.True(monitor.ValidCount >= 1);
            Assert.True(monitor.FailedCount >= 1);
        }

        [Fact]
        public void TimerStopsAfterDispose() {
            var monitor = new CertificateMonitor();
            monitor.Start(Array.Empty<string>(), TimeSpan.FromMilliseconds(10));
            Assert.True(monitor.IsRunning);
            monitor.Dispose();
            Assert.False(monitor.IsRunning);
        }
    }
}
