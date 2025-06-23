using System;

namespace DomainDetective.Tests {
    public class TestCertificateHTTP {
        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);
            Assert.False(analysis.IsReachable);
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
    }
}
