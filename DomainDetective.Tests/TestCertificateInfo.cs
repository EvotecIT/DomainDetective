using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests {
    public class TestCertificateInfo {
        [Fact]
        public async Task WeakCertificateFlagsSet() {
            var cert = new X509Certificate2("Data/weak.pem");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.WeakKey);
            Assert.True(analysis.Sha1Signature);
            Assert.Equal("RSA", analysis.KeyAlgorithm);
            Assert.Equal(1024, analysis.KeySize);
        }

        [Fact]
        public async Task StrongCertificateNotFlagged() {
            var cert = new X509Certificate2("Data/wildcard.pem");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.False(analysis.WeakKey);
            Assert.False(analysis.Sha1Signature);
            Assert.Equal(2048, analysis.KeySize);
        }

        [Fact]
        public async Task SelfSignedFlagSet() {
            var cert = new X509Certificate2("Data/wildcard.pem");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.IsSelfSigned);
        }
    }
}
