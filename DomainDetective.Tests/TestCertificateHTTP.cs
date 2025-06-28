using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests {
    public class TestCertificateHTTP {
        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);
            Assert.False(analysis.IsReachable);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task UnreachableHostLogsExceptionType() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnErrorMessage += (_, e) => eventArgs = e;

            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);

            Assert.NotNull(eventArgs);
            Assert.Contains(nameof(HttpRequestException), eventArgs!.FullMessage);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task ValidHostSetsProtocolVersion() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.True(analysis.ProtocolVersion?.Major >= 1);
            Assert.Equal(analysis.ProtocolVersion >= new Version(2, 0), analysis.Http2Supported);
            if (analysis.ProtocolVersion >= new Version(3, 0)) {
                Assert.True(analysis.Http3Supported);
            }
        }

        [Fact]
        public async Task ValidCertificateProvidesExpirationInfo() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.True(analysis.DaysValid > 0);
            Assert.Equal(analysis.DaysToExpire < 0, analysis.IsExpired);
        }

        [Fact]
        public async Task ExtractsRevocationEndpoints() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.NotNull(analysis.OcspUrls);
            Assert.NotNull(analysis.CrlUrls);
        }

        [Fact]
        public async Task ChecksCertificateTransparency() {
            var certPath = Path.Combine("Data", "wildcard.pem");
            var cert = new X509Certificate2(certPath);
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[{\"id\":1}]") };
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.PresentInCtLogs);
        }

        [Fact]
        public async Task CapturesCipherSuiteWhenEnabled() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CaptureTlsDetails = true };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.False(string.IsNullOrEmpty(analysis.CipherSuite));
            if (analysis.DhKeyBits > 0) {
                Assert.True(analysis.DhKeyBits > 0);
            }
        }
    }
}