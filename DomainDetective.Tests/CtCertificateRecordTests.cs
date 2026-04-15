using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public sealed class CtCertificateRecordTests {
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
        Assert.Null(record.Sha256Fingerprint);
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
