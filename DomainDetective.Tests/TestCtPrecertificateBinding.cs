using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DomainDetective.Tests;

public sealed class TestCtPrecertificateBinding {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteDecoding_BindsPrecertificateNamesToLoggedTbs(bool dedicatedSigner) {
        AsymmetricCipherKeyPair rootKey = Key(), signerKey = Key(), leafKey = Key();
        var rootName = new X509Name("CN=Fixture Root");
        var signerName = new X509Name("CN=Fixture Precertificate Signer");
        X509Certificate root = Certificate(rootName, rootName, rootKey, rootKey, ca: true);
        X509Certificate signer = Certificate(signerName, rootName, signerKey, rootKey, ca: true, ctSigner: true);
        X509Certificate final = Certificate(new X509Name("CN=login.example.test"), rootName, leafKey, rootKey);
        X509Certificate pre = Certificate(new X509Name("CN=login.example.test"), dedicatedSigner ? signerName : rootName,
            leafKey, dedicatedSigner ? signerKey : rootKey, poison: true, leafAuthority: dedicatedSigner ? (byte)2 : (byte)1);
        byte[] tbs = final.CertificateStructure.TbsCertificate.GetDerEncoded();
        byte[] issuerHash;
        using (var hash = System.Security.Cryptography.SHA256.Create())
            issuerHash = hash.ComputeHash(root.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded());
        byte[] leaf = new byte[] {0,0, 0,0,0,0,0,0,0,1, 0,1}.Concat(issuerHash).Concat(Vector(tbs)).Concat(new byte[] {0,0}).ToArray();
        byte[] chain = dedicatedSigner ? Vector(signer.GetEncoded()).Concat(Vector(root.GetEncoded())).ToArray() : Vector(root.GetEncoded());
        byte[] extra = Vector(pre.GetEncoded()).Concat(Vector(chain)).ToArray();
        var client = Client(leaf, extra);
        CtLogIngestionBatch batch = await client.ReadBatchAsync(Request());
        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(CtLogEntryType.Precertificate, entry.EntryType);
        Assert.Contains("login.example.test", entry.Certificate.DnsNames);
        Assert.Empty(batch.Diagnostics);

        // The extra data is outside the Merkle leaf. Altering it must not introduce unrelated names.
        X509Certificate altered = Certificate(new X509Name("CN=unrelated.example.test"), dedicatedSigner ? signerName : rootName,
            leafKey, dedicatedSigner ? signerKey : rootKey, poison: true, leafAuthority: dedicatedSigner ? (byte)2 : (byte)1);
        byte[] alteredExtra = Vector(altered.GetEncoded()).Concat(Vector(chain)).ToArray();
        CtEntryDecodingException error = await Assert.ThrowsAsync<CtEntryDecodingException>(() => Client(leaf, alteredExtra).ReadBatchAsync(Request()));
        Assert.Equal(0, error.EntryIndex);
        Assert.Equal(Convert.ToBase64String(alteredExtra), error.Payload.ExtraDataBase64);
    }

    private static CtLogIngestionBatchRequest Request() => new() {
        LogUrl = "https://ct.example.test/binding/", StartIndex = 0, BatchSize = 1, KnownTreeSize = 1, RequireCompleteDecoding = true
    };

    private static CtLogIngestionClient Client(byte[] leaf, byte[] extra) => new() {
        HttpGetOverride = (_, _) => Task.FromResult(JsonSerializer.Serialize(new {
            entries = new[] {new {leaf_input = Convert.ToBase64String(leaf), extra_data = Convert.ToBase64String(extra)}}
        }))
    };

    private static byte[] Vector(byte[] value) => new byte[] {(byte)(value.Length >> 16), (byte)(value.Length >> 8), (byte)value.Length}.Concat(value).ToArray();

    private static AsymmetricCipherKeyPair Key() {
        var curve = SecNamedCurves.GetByName("secp256r1");
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H), new SecureRandom()));
        return generator.GenerateKeyPair();
    }

    private static X509Certificate Certificate(X509Name subject, X509Name issuer, AsymmetricCipherKeyPair key,
        AsymmetricCipherKeyPair signingKey, bool ca = false, bool ctSigner = false, bool poison = false, byte leafAuthority = 1) {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.One);
        generator.SetIssuerDN(issuer);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc));
        generator.SetNotAfter(new DateTime(2027,1,1,0,0,0,DateTimeKind.Utc));
        generator.SetPublicKey(key.Public);
        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(new byte[] {leafAuthority}));
        if (ca) generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        else generator.AddExtension(X509Extensions.SubjectAlternativeName, false,
            new GeneralNames(new GeneralName(GeneralName.DnsName, subject.ToString().Substring(3))));
        if (ctSigner) generator.AddExtension(X509Extensions.ExtendedKeyUsage, true,
            new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")));
        if (poison) generator.AddExtension(new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.3"), true, DerNull.Instance);
        return generator.Generate(new Asn1SignatureFactory("SHA256withECDSA", signingKey.Private));
    }
}
