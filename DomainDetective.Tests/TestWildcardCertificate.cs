using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestWildcardCertificate {
        [Fact]
        public async Task DetectsWildcardAndSubdomains() {
            var cert = CertificateLoaderCompat.LoadCertificateFromFile("Data/wildcard.pem");
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.IsWildcardCertificate);
            Assert.True(analysis.WildcardSubdomains.ContainsKey("*.example.com"));
            var list = analysis.WildcardSubdomains["*.example.com"];
            Assert.Contains("a.example.com", list);
            Assert.Contains("b.example.com", list);
        }

        [Fact]
        public async Task WarnsOnUnrelatedHosts() {
            var cert = CertificateLoaderCompat.LoadCertificateFromFile("Data/multi.pem");
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.SecuresUnrelatedHosts);
        }
    }
}
