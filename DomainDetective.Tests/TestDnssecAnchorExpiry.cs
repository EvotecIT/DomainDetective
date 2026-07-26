using System;
using System.IO;
using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests {
    [Collection("DnssecCache")]
    public class TestDnssecAnchorExpiry {
        [Fact]
        public void AppliesBundledAnchorLifecycleMetadata() {
            var analysis = new DnsSecAnalysis();
            var logger = new InternalLogger();
            DateTimeOffset now = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
            DateTimeOffset expiration = now.AddDays(10);
            var anchors = new[] {
                new DnsSecTrustAnchor(12345, DnsKeyAlgorithm.RSASHA256, 2, "ABCD",
                    now.AddYears(-1), expiration)
            };

            analysis.ApplyTrustAnchorMetadata(anchors, now, logger);

            Assert.Equal(12345, analysis.RootKeyTag);
            Assert.Equal(expiration, analysis.RootAnchorExpiration);
            Assert.True(analysis.KeyExpiresSoon);
            Assert.Contains(analysis.Warnings, warning => warning.Contains("expires in 10 days", StringComparison.Ordinal));
        }

        [Fact]
        public async Task DetectsAnchorExpiry() {
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");
            Directory.CreateDirectory(cacheDir);

            DateTimeOffset expiry = DateTimeOffset.UtcNow.AddDays(10);
            string xml = $"<TrustAnchor><Zone>.</Zone><KeyDigest validFrom=\"2020-01-01T00:00:00+00:00\" validUntil=\"{expiry:yyyy-MM-ddTHH:mm:sszzz}\"><KeyTag>12345</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>ABC</Digest></KeyDigest></TrustAnchor>";
            File.WriteAllText(cacheFile, xml);
            File.SetLastWriteTimeUtc(cacheFile, DateTime.UtcNow);

            try {
                var result = await DomainDetective.DnsSecAnalysis.DownloadTrustAnchors();
                Assert.NotNull(result.expiration);
                Assert.True(result.expiration.Value - DateTimeOffset.UtcNow < TimeSpan.FromDays(30));
            } finally {
                File.Delete(cacheFile);
            }
        }
    }
}
