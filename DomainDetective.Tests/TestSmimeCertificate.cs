namespace DomainDetective.Tests {
    public class TestSmimeCertificate {
        [Fact]
        public void ParseCertificateFromFile() {
            var analysis = new SmimeCertificateAnalysis();
            var path = Path.Combine("Data", "smime.pem");
            analysis.AnalyzeFile(path);

            Assert.NotNull(analysis.Certificate);
            Assert.False(string.IsNullOrEmpty(analysis.Certificate.Subject));
            Assert.True(analysis.DaysValid > 0);
        }

        [Fact]
        public void ParseCertificateFromDirectoryAndFile() {
            var analysis = new SmimeCertificateAnalysis();
            var directory = $"Data{Path.DirectorySeparatorChar}";
            analysis.AnalyzeFile(directory, "smime.pem");

            Assert.NotNull(analysis.Certificate);
            Assert.False(string.IsNullOrEmpty(analysis.Certificate.Subject));
            Assert.True(analysis.DaysValid > 0);
        }
    }
}
