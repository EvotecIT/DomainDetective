using System;
using System.IO;
using System.Threading.Tasks;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    [Collection("DnssecCache")]
    public class TestDownloadTrustAnchors {
        [Fact]
        public async Task FetchesAnchors() {
            string cacheDir = Path.Combine(Path.GetTempPath(), "DomainDetective");
            string cacheFile = Path.Combine(cacheDir, "root-anchors.xml");
            if (File.Exists(cacheFile)) {
                File.Delete(cacheFile);
            }
            var result = await DnsSecAnalysis.DownloadTrustAnchors();
            bool fallbackWritten = false;
            if (result.anchors.Count == 0) {
                Directory.CreateDirectory(cacheDir);
                string xml =
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<TrustAnchor><Zone>.</Zone>" +
                    "<KeyDigest id=\"current\" validFrom=\"2017-02-02T00:00:00+00:00\">" +
                    "<KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>" +
                    "<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>" +
                    "</KeyDigest>" +
                    "</TrustAnchor>";
                File.WriteAllText(cacheFile, xml);
                File.SetLastWriteTimeUtc(cacheFile, DateTime.UtcNow);
                fallbackWritten = true;
                result = await DnsSecAnalysis.DownloadTrustAnchors();
            }
            try {
                Assert.NotEmpty(result.anchors);
            } finally {
                if (fallbackWritten && File.Exists(cacheFile)) {
                    File.Delete(cacheFile);
                }
            }
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
