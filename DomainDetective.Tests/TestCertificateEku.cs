using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateEku {
        [Fact]
        public async Task AnalyzeCertificateParsesServerAndClientEku() {
            using var cert = CreateSelfSignedWithEku(
                CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid,
                CertificateExtendedKeyUsageAnalyzer.ClientAuthenticationOid);
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };

            await analysis.AnalyzeCertificate(cert);

            Assert.True(analysis.HasEnhancedKeyUsageExtension);
            Assert.False(analysis.HasAnyExtendedKeyUsageOid);
            Assert.True(analysis.AllowsServerAuthentication);
            Assert.True(analysis.AllowsClientAuthentication);
            Assert.False(analysis.AllowsSecureEmail);
            Assert.Equal(CertificateAuthenticationProfileClassifier.ServerAndClientAuth, analysis.AuthenticationProfile);
            Assert.False(string.IsNullOrWhiteSpace(analysis.ChainSource));
            Assert.NotEmpty(analysis.ChainSourceHistory);
            Assert.Contains(CertificateExtendedKeyUsageAnalyzer.ServerAuthenticationOid, analysis.ExtendedKeyUsageOids);
            Assert.Contains(CertificateExtendedKeyUsageAnalyzer.ClientAuthenticationOid, analysis.ExtendedKeyUsageOids);
        }

        [Fact]
        public async Task AnalyzeCertificateWithoutEkuLeavesUsageFlagsFalse() {
            using var cert = CreateSelfSignedWithEku();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };

            await analysis.AnalyzeCertificate(cert);

            Assert.False(analysis.HasEnhancedKeyUsageExtension);
            Assert.False(analysis.AllowsServerAuthentication);
            Assert.False(analysis.AllowsClientAuthentication);
            Assert.False(analysis.AllowsSecureEmail);
            Assert.Equal(CertificateAuthenticationProfileClassifier.NoEkuExtension, analysis.AuthenticationProfile);
            Assert.Empty(analysis.ExtendedKeyUsageOids);
        }

        [Fact]
        public async Task AnalyzeCertificateWithAnyEkuUsesAnyProfile() {
            using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.AnyExtendedKeyUsageOid);
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };

            await analysis.AnalyzeCertificate(cert);

            Assert.True(analysis.HasAnyExtendedKeyUsageOid);
            Assert.True(analysis.AllowsServerAuthentication);
            Assert.True(analysis.AllowsClientAuthentication);
            Assert.True(analysis.AllowsSecureEmail);
            Assert.Equal(CertificateAuthenticationProfileClassifier.AnyExtendedKeyUsage, analysis.AuthenticationProfile);
        }

        [Fact]
        public void SmimeAnalysisParsesSecureEmailEkuViaSharedParser() {
            using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.SecureEmailOid);
            var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
            File.WriteAllBytes(tempPath, cert.Export(X509ContentType.Cert));
            try {
                var analysis = new SmimeCertificateAnalysis();
                analysis.AnalyzeFile(tempPath);
                Assert.True(analysis.HasSecureEmailEku);
            } finally {
                if (File.Exists(tempPath)) {
                    File.Delete(tempPath);
                }
            }
        }

        [Fact]
        public void SmimeAnalysisDoesNotTreatAnyEkuAsSecureEmail() {
            using var cert = CreateSelfSignedWithEku(CertificateExtendedKeyUsageAnalyzer.AnyExtendedKeyUsageOid);
            var tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cer");
            File.WriteAllBytes(tempPath, cert.Export(X509ContentType.Cert));
            try {
                var analysis = new SmimeCertificateAnalysis();
                analysis.AnalyzeFile(tempPath);
                Assert.False(analysis.HasSecureEmailEku);
            } finally {
                if (File.Exists(tempPath)) {
                    File.Delete(tempPath);
                }
            }
        }

        [Fact]
        public void AnalyzeMalformedEkuExtensionDoesNotThrow() {
            using var cert = CreateSelfSignedWithRawEku(new byte[] { 0x30, 0x01, 0x06 });

            var usage = CertificateExtendedKeyUsageAnalyzer.Analyze(cert);

            Assert.True(usage.HasEnhancedKeyUsageExtension);
            Assert.Empty(usage.Oids);
            Assert.Equal(CertificateAuthenticationProfileClassifier.EkuPresentNoUsages, usage.AuthenticationProfile);
        }

        private static X509Certificate2 CreateSelfSignedWithEku(params string[] ekuOids) {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=eku.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (ekuOids != null && ekuOids.Length > 0) {
                var collection = new OidCollection();
                foreach (var oid in ekuOids) {
                    collection.Add(new Oid(oid));
                }
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(collection, false));
            }

            var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Cert));
        }

        private static X509Certificate2 CreateSelfSignedWithRawEku(byte[] rawEkuExtension) {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=eku.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509Extension(new Oid("2.5.29.37"), rawEkuExtension, false));

            var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Cert));
        }
    }
}
