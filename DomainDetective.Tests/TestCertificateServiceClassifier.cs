namespace DomainDetective.Tests {
    public class TestCertificateServiceClassifier {
        [Fact]
        public void ResolveDefaultsToHttpsAndDefaultPort() {
            var descriptor = CertificateServiceClassifier.Resolve("example.com", 443);

            Assert.Equal("https://example.com/", descriptor.Url);
            Assert.Equal("example.com", descriptor.Host);
            Assert.Equal("https", descriptor.Scheme);
            Assert.Equal(443, descriptor.Port);
            Assert.Equal("HTTPS", descriptor.Service);
        }

        [Fact]
        public void ResolvePreservesExplicitPortFromInput() {
            var descriptor = CertificateServiceClassifier.Resolve("https://example.com:8443/app", 443);

            Assert.Equal(8443, descriptor.Port);
            Assert.Equal("HTTPS-Alt", descriptor.Service);
            Assert.Equal("https://example.com:8443/app", descriptor.Url);
        }
    }
}
