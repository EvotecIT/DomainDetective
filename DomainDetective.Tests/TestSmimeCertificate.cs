namespace DomainDetective.Tests {
    public class TestSmimeCertificate {
        [Fact]
        public void ParseCertificateFromFile() {
            var analysis = new SmimeCertificateAnalysis();
            analysis.AnalyzeFile("Data/smime.pem");

            Assert.NotNull(analysis.Certificate);
            Assert.False(string.IsNullOrEmpty(analysis.Certificate.Subject));
            Assert.True(analysis.DaysValid > 0);
        }
    }
}
