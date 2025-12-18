using System;
using System.IO;
using System.Threading.Tasks;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDownloadTrustAnchors {
        [Fact]
        public async Task FetchesAnchors() {
            var result = await DnsSecAnalysis.DownloadTrustAnchors();
            Assert.NotEmpty(result.anchors);
        }

        [Fact]
        public async Task IgnoresExpiredKeyDigestsWhenActivePresent() {
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");
            Directory.CreateDirectory(cacheDir);

            string xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<TrustAnchor><Zone>.</Zone>" +
                "<KeyDigest id=\"old\" validFrom=\"2010-07-15T00:00:00+00:00\" validUntil=\"2019-01-11T00:00:00+00:00\">" +
                "<KeyTag>19036</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>ABC</Digest>" +
                "</KeyDigest>" +
                "<KeyDigest id=\"current\" validFrom=\"2017-02-02T00:00:00+00:00\">" +
                "<KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>DEF</Digest>" +
                "</KeyDigest>" +
                "<KeyDigest id=\"future\" validFrom=\"2099-01-01T00:00:00+00:00\">" +
                "<KeyTag>99999</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>GHI</Digest>" +
                "</KeyDigest>" +
                "</TrustAnchor>";
            File.WriteAllText(cacheFile, xml);
            File.SetLastWriteTimeUtc(cacheFile, DateTime.UtcNow);

            try {
                var result = await DnsSecAnalysis.DownloadTrustAnchors();
                Assert.Contains(result.anchors, a => a.StartsWith("20326 ", StringComparison.Ordinal));
                Assert.DoesNotContain(result.anchors, a => a.StartsWith("19036 ", StringComparison.Ordinal));
                Assert.DoesNotContain(result.anchors, a => a.StartsWith("99999 ", StringComparison.Ordinal));
                Assert.Null(result.expiration);
            } finally {
                File.Delete(cacheFile);
            }
        }

        [Fact]
        public async Task MalformedXmlReturnsEmpty() {
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");
            Directory.CreateDirectory(cacheDir);
            File.WriteAllText(cacheFile, "<trustanchors><bad></trust>");
            File.SetLastWriteTimeUtc(cacheFile, DateTime.UtcNow);

            try {
                var result = await DnsSecAnalysis.DownloadTrustAnchors();
                Assert.Empty(result.anchors);
            } finally {
                File.Delete(cacheFile);
            }
        }
    }
}
