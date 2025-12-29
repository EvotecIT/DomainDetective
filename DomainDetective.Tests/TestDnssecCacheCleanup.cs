using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    [Collection("DnssecCache")]
    public class TestDnssecCacheCleanup {
        [Fact]
        public async Task DeletesCacheFileOnCancel() {
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");
            if (File.Exists(cacheFile)) {
                File.Delete(cacheFile);
            }
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DnsSecAnalysis.DownloadTrustAnchors(null, cts.Token));
            Assert.False(File.Exists(cacheFile));
        }
    }
}
