using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using Xunit;

namespace DomainDetective.Tests;

public class TestOcspParser {
    [Fact]
    public void UnknownStatusReturnsNull() {
        byte[] data = CreateOcspResponse(new UnknownStatus());
        bool? result = CertificateAnalysis.ParseOcspResponse(data);
        Assert.Null(result);
    }

    [Fact]
    public void RevokedStatusReturnsTrue() {
        byte[] data = CreateOcspResponse(new RevokedStatus(DateTime.UtcNow, CrlReason.PrivilegeWithdrawn));
        bool? result = CertificateAnalysis.ParseOcspResponse(data);
        Assert.True(result);
    }

    [Fact]
    public void GoodStatusReturnsFalse() {
        byte[] data = CreateOcspResponse(null);
        bool? result = CertificateAnalysis.ParseOcspResponse(data);
        Assert.False(result);
    }

    private static byte[] CreateOcspResponse(CertificateStatus? status) {
        var random = new SecureRandom();
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(random, 2048));
        AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();
        var name = new X509Name("CN=Test");
        var serial = BigInteger.One;
        certGen.SetSerialNumber(serial);
        certGen.SetIssuerDN(name);
        certGen.SetSubjectDN(name);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
        certGen.SetPublicKey(keyPair.Public);
        var sigFactory = new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private);
        X509Certificate cert = certGen.Generate(sigFactory);

        var id = new CertificateID(CertificateID.DigestSha1, cert, serial);
        var respGen = new BasicOcspRespGenerator(keyPair.Public);
        respGen.AddResponse(id, status);
        var basic = respGen.Generate(sigFactory, null, DateTime.UtcNow);
        var ocspGen = new OCSPRespGenerator();
        var ocspResp = ocspGen.Generate(OcspRespStatus.Successful, basic);
        return ocspResp.GetEncoded();
    }
}