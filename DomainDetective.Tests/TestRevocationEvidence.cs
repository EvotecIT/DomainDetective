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

public partial class TestRevocationEvidence {
    private static readonly DateTime Now = new(2026, 10, 5, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("good", false)]
    [InlineData("revoked", true)]
    [InlineData("unknown", null)]
    [InlineData("tampered", null)]
    [InlineData("stale", null)]
    [InlineData("future", null)]
    [InlineData("wrong-certificate", null)]
    [InlineData("wrong-issuer", null)]
    [InlineData("unauthorized", null)]
    [InlineData("duplicate", null)]
    [InlineData("trailing", null)]
    public void OcspVerdictRequiresFreshAuthorizedEvidenceForTheRequestedCertificate(string scenario, bool? expected) {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys);
        var signerKeys = scenario == "unauthorized" ? Keys() : issuerKeys;
        var responseIssuer = scenario == "wrong-issuer" ? Certificate("CN=Other issuer", BigInteger.One, Keys(), null, null, ca: true) : issuer;
        var id = new CertificateID(CertificateID.DigestSha1, responseIssuer, scenario == "wrong-certificate" ? BigInteger.Two : leaf.SerialNumber);
        var generator = new BasicOcspRespGenerator(signerKeys.Public);
        CertificateStatus? status = scenario == "revoked" ? new RevokedStatus(Now.AddMinutes(-10), CrlReason.KeyCompromise)
            : scenario == "unknown" ? new UnknownStatus() : null;
        DateTime update = scenario == "stale" ? Now.AddDays(-2) : scenario == "future" ? Now.AddDays(1) : Now.AddMinutes(-10);
        DateTime next = update.AddHours(1);
        generator.AddResponse(id, status, update, next, null);
        if (scenario == "duplicate") generator.AddResponse(id, new RevokedStatus(Now.AddMinutes(-5), CrlReason.KeyCompromise), update, next, null);
        var basic = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", signerKeys.Private), null, update);
        byte[] bytes = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basic).GetEncoded();
        if (scenario == "tampered") bytes[bytes.Length - 1] ^= 1;
        if (scenario == "trailing") bytes = System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Concat(bytes, new byte[] { 0 }));
        Assert.Equal(expected, ParseOcsp(bytes, leaf, issuer));
    }

    private static bool? ParseOcsp(byte[] bytes, X509Certificate leaf, X509Certificate issuer) => CertificateAnalysis.ParseOcspResponse(bytes, leaf, issuer, Now);

    [Theory]
    [InlineData("good", false)]
    [InlineData("revoked", true)]
    [InlineData("tampered", null)]
    [InlineData("stale", null)]
    [InlineData("future", null)]
    [InlineData("wrong-issuer", null)]
    [InlineData("delta", null)]
    [InlineData("scoped", null)]
    public void CrlVerdictRequiresAnAuthenticatedCurrentCompleteIssuerList(string scenario, bool? expected) {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys);
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(scenario == "wrong-issuer" ? new X509Name("CN=Other issuer") : issuer.SubjectDN);
        DateTime update = scenario == "stale" ? Now.AddDays(-2) : scenario == "future" ? Now.AddDays(1) : Now.AddMinutes(-10);
        generator.SetThisUpdate(update); generator.SetNextUpdate(update.AddHours(1));
        if (scenario == "revoked") generator.AddCrlEntry(leaf.SerialNumber, Now.AddMinutes(-5), CrlReason.KeyCompromise);
        if (scenario == "delta") generator.AddExtension(X509Extensions.DeltaCrlIndicator, true, Org.BouncyCastle.Asn1.DerInteger.ValueOf(1));
        if (scenario == "scoped") generator.AddExtension(X509Extensions.IssuingDistributionPoint, true,
            new IssuingDistributionPoint(null, true, false, null, false, false));
        byte[] bytes = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", issuerKeys.Private)).GetEncoded();
        if (scenario == "tampered") bytes[bytes.Length - 1] ^= 1;
        Assert.Equal(expected, CertificateRevocationEvidence.CrlStatus(bytes, leaf, issuer, Now));
    }

    [Theory]
    [InlineData(true, true, false)]
    [InlineData(false, true, null)]
    [InlineData(true, false, null)]
    public void DelegatedOcspSignerRequiresIssuerAuthorizationAndNoCheck(bool ocspPurpose, bool noCheck, bool? expected) {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys);
        var responderKeys = Keys();
        var responder = Certificate("CN=Responder", BigInteger.Two, responderKeys, issuer, issuerKeys, ocspPurpose: ocspPurpose, noCheck: noCheck);
        var generator = new BasicOcspRespGenerator(responderKeys.Public);
        generator.AddResponse(new CertificateID(CertificateID.DigestSha1, issuer, leaf.SerialNumber), null, Now.AddMinutes(-10), Now.AddHours(1), null);
        var response = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", responderKeys.Private), new[] { responder }, Now);
        var bytes = new OCSPRespGenerator().Generate(OcspRespStatus.Successful, response).GetEncoded();
        Assert.Equal(expected, ParseOcsp(bytes, leaf, issuer));
    }

    [Fact]
    public void DelegatedOcspSignerWithAnUnsupportedCriticalExtensionIsNotAuthorized() {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys);
        var responderKeys = Keys();
        var responder = Certificate("CN=Responder", BigInteger.Two, responderKeys, issuer, issuerKeys,
            ocspPurpose: true, noCheck: true, unknownCritical: true);
        var generator = new BasicOcspRespGenerator(responderKeys.Public);
        generator.AddResponse(new CertificateID(CertificateID.DigestSha1, issuer, leaf.SerialNumber), null, Now.AddMinutes(-10), Now.AddHours(1), null);
        var response = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", responderKeys.Private), new[] { responder }, Now);
        Assert.Null(ParseOcsp(new OCSPRespGenerator().Generate(OcspRespStatus.Successful, response).GetEncoded(), leaf, issuer));
    }

    [Theory]
    [InlineData(KeyUsage.NonRepudiation, false)]
    [InlineData(KeyUsage.DigitalSignature, true)]
    public void RecognizedDelegatedOcspAuthorizationVariantsRemainUsable(int keyUsage, bool criticalNoCheck) {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys);
        var responderKeys = Keys();
        var responder = Certificate("CN=Responder", BigInteger.Two, responderKeys, issuer, issuerKeys,
            ocspPurpose: true, noCheck: true, keyUsage: keyUsage, criticalNoCheck: criticalNoCheck);
        var generator = new BasicOcspRespGenerator(responderKeys.Public);
        generator.AddResponse(new CertificateID(CertificateID.DigestSha1, issuer, leaf.SerialNumber), null, Now.AddMinutes(-10), Now.AddHours(1), null);
        var response = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", responderKeys.Private), new[] { responder }, Now);
        Assert.Equal(false, ParseOcsp(new OCSPRespGenerator().Generate(OcspRespStatus.Successful, response).GetEncoded(), leaf, issuer));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void CertificateDistributionPointScopeCannotBeTreatedAsCompleteIssuerEvidence(bool limitedReasons, bool namedCrlIssuer) {
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys,
            crlUrl: "http://crl.example.test/list", limitedCrlReasons: limitedReasons, namedCrlIssuer: namedCrlIssuer);
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(issuer.SubjectDN); generator.SetThisUpdate(Now.AddMinutes(-10)); generator.SetNextUpdate(Now.AddHours(1));
        byte[] bytes = generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", issuerKeys.Private)).GetEncoded();
        Assert.Null(CertificateRevocationEvidence.CrlStatus(bytes, leaf, issuer, Now));
    }

    private static AsymmetricCipherKeyPair Keys() {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return generator.GenerateKeyPair();
    }

    private static X509Certificate Certificate(string name, BigInteger serial, AsymmetricCipherKeyPair keys,
        X509Certificate? issuer, AsymmetricCipherKeyPair? issuerKeys, bool ca = false, bool ocspPurpose = false, bool noCheck = false, bool unknownCritical = false, string? ocspUrl = null, string? crlUrl = null, int? keyUsage = null, bool criticalNoCheck = false, bool limitedCrlReasons = false, bool namedCrlIssuer = false) {
        var generator = new X509V3CertificateGenerator();
        var subject = new X509Name(name);
        generator.SetSerialNumber(serial); generator.SetIssuerDN(issuer?.SubjectDN ?? subject); generator.SetSubjectDN(subject);
        generator.SetNotBefore(Now.AddDays(-1)); generator.SetNotAfter(Now.AddDays(1)); generator.SetPublicKey(keys.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage ?? (ca ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature)));
        if (ocspUrl != null) generator.AddExtension(X509Extensions.AuthorityInfoAccess, false,
            new AuthorityInformationAccess(new AccessDescription(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.5.5.7.48.1"), new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl))));
        if (crlUrl != null) generator.AddExtension(X509Extensions.CrlDistributionPoints, false,
            new CrlDistPoint(new[] { new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, crlUrl))), limitedCrlReasons ? new ReasonFlags(ReasonFlags.KeyCompromise) : null, namedCrlIssuer ? new GeneralNames(new GeneralName(issuer!.SubjectDN)) : null) }));
        if (ocspPurpose) generator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeID.id_kp_OCSPSigning));
        if (noCheck) generator.AddExtension(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.5.5.7.48.1.5"), criticalNoCheck, Org.BouncyCastle.Asn1.DerNull.Instance);
        if (unknownCritical) generator.AddExtension(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.2.3.4.5"), true, Org.BouncyCastle.Asn1.DerNull.Instance);
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", (issuerKeys ?? keys).Private));
    }
}
