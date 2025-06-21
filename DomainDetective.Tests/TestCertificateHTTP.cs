namespace DomainDetective.Tests {
    public class TestCertificateHTTP {
        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);
            Assert.False(analysis.IsReachable);
        }
    }
}
