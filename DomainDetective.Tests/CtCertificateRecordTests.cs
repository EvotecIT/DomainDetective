using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public sealed class CtCertificateRecordTests {
    [Theory]
    [InlineData("pkcs7")]
    [InlineData("pem")]
    [InlineData("trailing")]
    [InlineData("concatenated")]
    [InlineData("ber")]
    public void FromDer_RejectsAnythingExceptOneCompleteDerCertificate(string encoding) {
        byte[] der = CreateCertificateDer("boundary.example.test", "www.boundary.example.test");
        byte[] input;
        if (encoding == "pkcs7") {
            using X509Certificate2 certificate = Helpers.CertificateLoaderCompat.LoadCertificate(der);
            input = new X509Certificate2Collection(certificate).Export(X509ContentType.Pkcs7)!;
        } else if (encoding == "pem") {
            input = System.Text.Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der) + "\n-----END CERTIFICATE-----");
        } else if (encoding == "ber") {
            int headerLength = 2 + (der[1] & 0x7f);
            input = new byte[] { 0x30, 0x80 }.Concat(der.Skip(headerLength)).Concat(new byte[] { 0, 0 }).ToArray();
        } else {
            input = der.Concat(encoding == "trailing" ? new byte[] { 0 } : der).ToArray();
        }

        Assert.Throws<CryptographicException>(() => CtCertificateRecord.FromDer(
            CtProviderProfiles.NativeCtProviderId, input, detailLevel: CtCertificateRecordDetailLevel.NamesOnly));
    }

    [Fact]
    public void FromDer_NamesOnly_PopulatesDnsNames_WithoutFullMetadata() {
        byte[] certificateDer = CreateCertificateDer("names-only.example.test", "www.names-only.example.test");

        CtCertificateRecord record = CtCertificateRecord.FromDer(
            CtProviderProfiles.NativeCtProviderId,
            certificateDer,
            providerCertificateId: "test-cert",
            detailLevel: CtCertificateRecordDetailLevel.NamesOnly);

        Assert.Equal(CtCertificateRecordDetailLevel.NamesOnly, record.DetailLevel);
        Assert.Contains("names-only.example.test", record.DnsNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("www.names-only.example.test", record.DnsNames, StringComparer.OrdinalIgnoreCase);
        Assert.NotNull(record.Sha256Fingerprint);
        Assert.Null(record.Subject);
        Assert.NotNull(record.CertificateDer);
        Assert.Equal(certificateDer, record.CertificateDer);
    }

    [Fact]
    public void EnsureFullDetails_HydratesNamesOnlyRecord() {
        byte[] certificateDer = CreateCertificateDer("hydrate.example.test", "api.hydrate.example.test");
        CtCertificateRecord namesOnlyRecord = CtCertificateRecord.FromDer(
            CtProviderProfiles.NativeCtProviderId,
            certificateDer,
            providerCertificateId: "test-cert",
            detailLevel: CtCertificateRecordDetailLevel.NamesOnly);

        CtCertificateRecord hydrated = namesOnlyRecord.EnsureFullDetails();

        Assert.Equal(CtCertificateRecordDetailLevel.Full, hydrated.DetailLevel);
        Assert.NotNull(hydrated.Sha256Fingerprint);
        Assert.NotNull(hydrated.Subject);
        Assert.NotNull(hydrated.NotBeforeUtc);
        Assert.NotNull(hydrated.NotAfterUtc);
        Assert.Contains("hydrate.example.test", hydrated.DnsNames, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("api.hydrate.example.test", hydrated.DnsNames, StringComparer.OrdinalIgnoreCase);
    }

    private static byte[] CreateCertificateDer(string commonName, string sanName) {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(commonName);
        sanBuilder.AddDnsName(sanName);
        request.CertificateExtensions.Add(sanBuilder.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return certificate.Export(X509ContentType.Cert);
    }
}
