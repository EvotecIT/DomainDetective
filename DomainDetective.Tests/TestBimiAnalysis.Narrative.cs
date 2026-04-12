using DnsClientX;
using DomainDetective.Tests.Fixtures;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DomainDetective.Tests {
    public partial class TestBimiAnalysis {
        [Fact]
        public async Task BimiNarrativeAndRecommendations() {
            using var vmc = CreateTrustedVmc(out var root);
            using var cert = CreateSelfSigned();
            var server = new TcpListenerFixture((l, t) => RunServer(l, cert, path =>
                path.EndsWith(".svg")
                    ? ("image/svg+xml", Encoding.UTF8.GetBytes("<svg width='64' height='64' viewBox='0 0 64 64'></svg>"))
                    : ("application/pkix-cert", vmc.Export(X509ContentType.Cert)), t));
            await server.InitializeAsync();
            var prefix = $"https://localhost:{server.Port}/";
            try {
                var record = $"v=BIMI1; l={prefix}logo.svg; a={prefix}vmc.cer";
                var answers = new List<DnsAnswer> { new() { DataRaw = record, Type = DnsRecordType.TXT } };
                var analysis = CreateBimiAnalysisIgnoreSsl();
                analysis.TrustedRoots.Add(root);
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                var codes = analysis.Recommendations.Select(r => r.Code).ToList();
                Assert.Contains(BimiCodes.SvgValid, codes);
                Assert.Contains(BimiCodes.VmcVerified, codes);

                var narrative = DomainDetective.Narratives.BimiNarrative.Build(analysis);
                Assert.Contains(narrative.Highlights, h => h.Contains("BIMI record is published"));
                Assert.Contains(narrative.Highlights, h => h.Contains("SVG"));
                Assert.Contains(narrative.Highlights, h => h.Contains("certificate"));
            } finally {
                await server.DisposeAsync();
            }
        }

        private static X509Certificate2 CreateTrustedVmc(out X509Certificate2 root) {
            using var rootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=RootCA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
            var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            root = CertificateLoaderCompat.LoadPkcs12(rootCert.Export(X509ContentType.Pfx));

            using var leafKey = RSA.Create(2048);
            var leafReq = new CertificateRequest("CN=example", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            leafReq.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.12", Encoding.ASCII.GetBytes("image/svg+xml"), false));
            var serial = new byte[8];
            using (var rng = RandomNumberGenerator.Create()) {
                rng.GetBytes(serial);
            }
            var leafCert = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
            return CertificateLoaderCompat.LoadPkcs12(leafCert.Export(X509ContentType.Pfx));
        }
}
}
