using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestWildcardCertificate {
        [Fact]
        public async Task DetectsWildcardAndSubdomains() {
            var cert = new X509Certificate2("Data/wildcard.pem");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.IsWildcardCertificate);
            Assert.True(analysis.WildcardSubdomains.ContainsKey("*.example.com"));
            var list = analysis.WildcardSubdomains["*.example.com"];
            Assert.Contains("a.example.com", list);
            Assert.Contains("b.example.com", list);
        }

        [Fact]
        public async Task WarnsOnUnrelatedHosts() {
            var cert = new X509Certificate2("Data/multi.pem");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.SecuresUnrelatedHosts);
        }
    }
}
