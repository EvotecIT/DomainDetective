namespace DomainDetective.Tests {
    public class TestCertificateIssuerClassifier {
        [Fact]
        public void ClassifyDetectsKnownLetsEncryptIssuer() {
            var issuer = "CN=R3, O=Let's Encrypt, C=US";
            var classified = CertificateIssuerClassifier.Classify(issuer);

            Assert.True(classified.IsKnownAuthority);
            Assert.Equal("Let's Encrypt", classified.NormalizedName);
            Assert.Equal("LetsEncrypt", classified.AuthorityFamily);
            Assert.Equal("Let's Encrypt", classified.Organization);
        }

        [Fact]
        public void ClassifyDetectsKnownDigiCertIssuer() {
            var issuer = "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US";
            var classified = CertificateIssuerClassifier.Classify(issuer);

            Assert.True(classified.IsKnownAuthority);
            Assert.Equal("DigiCert", classified.NormalizedName);
            Assert.Equal("DigiCert", classified.AuthorityFamily);
            Assert.Equal("DigiCert Inc", classified.Organization);
        }

        [Fact]
        public void ClassifyFallsBackToOrganizationForUnknownIssuer() {
            var issuer = "CN=Custom Internal Issuing CA, O=Contoso Security, C=US";
            var classified = CertificateIssuerClassifier.Classify(issuer);

            Assert.False(classified.IsKnownAuthority);
            Assert.Equal("Contoso Security", classified.NormalizedName);
            Assert.Null(classified.AuthorityFamily);
        }

        [Fact]
        public void ClassifyDoesNotUseShortLetsEncryptTokensAsSubstrings() {
            var issuer = "CN=CorpR3 Issuing CA, O=Example Security, C=US";
            var classified = CertificateIssuerClassifier.Classify(issuer);

            Assert.False(classified.IsKnownAuthority);
            Assert.Equal("Example Security", classified.NormalizedName);
        }

        [Fact]
        public void ClassifyDetectsLetsEncryptByExactIntermediateCommonName() {
            var issuer = "CN=R3, O=Internal PKI Name Collision Test, C=US";
            var classified = CertificateIssuerClassifier.Classify(issuer);

            Assert.True(classified.IsKnownAuthority);
            Assert.Equal("Let's Encrypt", classified.NormalizedName);
            Assert.Equal("LetsEncrypt", classified.AuthorityFamily);
        }
    }
}
