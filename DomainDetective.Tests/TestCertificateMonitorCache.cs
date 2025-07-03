using System;
using System.IO;
using Xunit;

namespace DomainDetective.Tests {
    public class TestCertificateMonitorCache {
        [Fact]
        public void RemovesExpiredFiles() {
            var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(dir);
            var oldFile = Path.Combine(dir, "old.txt");
            File.WriteAllText(oldFile, string.Empty);
            File.SetLastWriteTimeUtc(oldFile, DateTime.UtcNow - TimeSpan.FromDays(2));
            var newFile = Path.Combine(dir, "new.txt");
            File.WriteAllText(newFile, string.Empty);

            var monitor = new CertificateMonitor {
                CacheDirectory = dir,
                CacheRetention = TimeSpan.FromDays(1)
            };
            monitor.Start(Array.Empty<string>(), TimeSpan.FromDays(1));
            monitor.Stop();

            Assert.False(File.Exists(oldFile));
            Assert.True(File.Exists(newFile));

            Directory.Delete(dir, true);
        }
    }
}
