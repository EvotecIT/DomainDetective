using System.Net.Http;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
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
    public async Task StaticDedicatedPrecertificatesReuseValidatedIssuersWithinOneBatch(bool oversizedIssuer) {
        AsymmetricCipherKeyPair rootKey = Key(), signerKey = Key(), leafKey = Key();
        var rootName = new X509Name("CN=Fixture Root");
        var signerName = new X509Name("CN=Fixture Precertificate Signer");
        X509Certificate root = Certificate(rootName, rootName, rootKey, rootKey, ca: true, paddingBytes: oversizedIssuer ? 65536 : 0);
        X509Certificate signer = Certificate(signerName, rootName, signerKey, rootKey, ca: true, ctSigner: true);
        X509Certificate final = Certificate(new X509Name("CN=login.example.test"), rootName, leafKey, rootKey);
        X509Certificate pre = Certificate(new X509Name("CN=login.example.test"), signerName,
            leafKey, signerKey, poison: true, leafAuthority: 2);
        byte[] rootBytes = root.GetEncoded(), signerBytes = signer.GetEncoded();
        byte[] fingerprints = Hash(signerBytes).Concat(Hash(rootBytes)).ToArray();
        byte[] leaf = new byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 }
            .Concat(Hash(root.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded()))
            .Concat(Vector(final.CertificateStructure.TbsCertificate.GetDerEncoded())).Concat(new byte[] { 0, 0 }).ToArray();
        byte[] entry = leaf.Concat(Vector(pre.GetEncoded())).Concat(new byte[] { 0, 64 }).Concat(fingerprints).ToArray();
        byte[] tile = Enumerable.Range(0, 32).SelectMany(_ => entry).ToArray();
        int issuerRequests = 0;
        bool corruptIssuer = false;
        var client = new CtLogIngestionClient {
            SendOverride = (message, _) => {
                bool issuer = message.RequestUri!.AbsolutePath.Contains("/issuer/");
                if (issuer) issuerRequests++;
                byte[] content = issuer
                    ? (corruptIssuer || !message.RequestUri.AbsolutePath.EndsWith(Hex(Hash(signerBytes))) ? rootBytes : signerBytes)
                    : tile;
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(content) });
            }
        };
        var request = new CtLogIngestionBatchRequest {
            LogUrl = "https://ct.example.test/binding/", MonitoringUrl = "https://ct.example.test/binding/", ApiKind = CtLogApiKind.StaticCt,
            StartIndex = 0, BatchSize = 32, KnownTreeSize = 32, RequireCompleteDecoding = true
        };
        CtLogIngestionBatch batch = await client.ReadBatchAsync(request);
        Assert.Equal(32, batch.Entries.Count);
        Assert.All(batch.Entries, value => Assert.Contains("login.example.test", value.Certificate.DnsNames));
        int expectedRequests = oversizedIssuer ? 33 : 2;
        Assert.Equal(expectedRequests, issuerRequests);

        // A new batch fetches and validates anew; reuse never accepts a mismatched issuer fingerprint.
        corruptIssuer = true;
        await Assert.ThrowsAsync<CtEntryDecodingException>(() => client.ReadBatchAsync(request));
        Assert.Equal(expectedRequests + 1, issuerRequests);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CompleteDecoding_RejectsCertificateContainers(bool isStatic, bool issuerContainer) {
        AsymmetricCipherKeyPair rootKey = Key(), signerKey = Key(), leafKey = Key();
        var rootName = new X509Name("CN=Boundary Root");
        var signerName = new X509Name("CN=Boundary Signer");
        X509Certificate root = Certificate(rootName, rootName, rootKey, rootKey, ca: true);
        X509Certificate signer = Certificate(signerName, rootName, signerKey, rootKey, ca: true, ctSigner: true);
        X509Certificate final = Certificate(new X509Name("CN=logged.example.test"), rootName, leafKey, rootKey);
        X509Certificate pre = Certificate(new X509Name("CN=logged.example.test"), issuerContainer ? signerName : rootName,
            leafKey, issuerContainer ? signerKey : rootKey, poison: true, leafAuthority: issuerContainer ? (byte)2 : (byte)1);
        byte[] tbs = final.CertificateStructure.TbsCertificate.GetDerEncoded();
        byte[] issuerHash = Hash(root.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded());
        byte[] leaf = new byte[] {0,0, 0,0,0,0,0,0,0,1, 0,1}.Concat(issuerHash).Concat(Vector(tbs)).Concat(new byte[] {0,0}).ToArray();
        byte[] certificateBytes = issuerContainer ? pre.GetEncoded() : Pkcs7(pre);
        byte[] signerBytes = issuerContainer ? Pkcs7(signer) : signer.GetEncoded();
        byte[] rootBytes = root.GetEncoded();
        byte[] extra = Vector(certificateBytes).Concat(Vector(Vector(signerBytes).Concat(Vector(rootBytes)).ToArray())).ToArray();
        CtLogIngestionClient client = Client(leaf, extra);
        CtLogIngestionBatchRequest request = Request();
        if (isStatic) {
            byte[] fingerprints = issuerContainer ? Hash(signerBytes).Concat(Hash(rootBytes)).ToArray() : Array.Empty<byte>();
            byte[] tile = leaf.Skip(2).Concat(Vector(certificateBytes))
                .Concat(new byte[] {(byte)(fingerprints.Length >> 8), (byte)fingerprints.Length}).Concat(fingerprints).ToArray();
            client = new CtLogIngestionClient {
                SendOverride = (message, _) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) {
                    Content = new ByteArrayContent(message.RequestUri!.AbsolutePath.Contains("/issuer/") ?
                        (message.RequestUri.AbsolutePath.EndsWith(Hex(Hash(signerBytes))) ? signerBytes : rootBytes) : tile)
                })
            };
            request = new CtLogIngestionBatchRequest {
                LogUrl = "https://ct.example.test/binding/", MonitoringUrl = "https://ct.example.test/binding/", ApiKind = CtLogApiKind.StaticCt,
                StartIndex = 0, BatchSize = 1, KnownTreeSize = 1, RequireCompleteDecoding = true
            };
        }

        CtEntryDecodingException error = await Assert.ThrowsAsync<CtEntryDecodingException>(() => client.ReadBatchAsync(request));
        Assert.Equal(0, error.EntryIndex);
        Assert.NotEmpty(error.Payload.ExtraDataBase64);
    }

    private static byte[] Pkcs7(X509Certificate certificate) {
        AsymmetricCipherKeyPair key = Key();
        // Keep the logged certificate first even when the CMS certificate SET is DER-sorted.
        string unit = new string('x', 64);
        var name = new X509Name($"CN=unrelated.example.test,OU={unit},OU={unit},OU={unit}");
        X509Certificate unrelated = Certificate(name, name, key, key, ca: true);
        var digestAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        var signatureAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.10045.4.3.2"));
        var signer = new DerSequence(DerInteger.ValueOf(1),
            new IssuerAndSerialNumber(unrelated.IssuerDN, unrelated.SerialNumber), digestAlgorithm,
            signatureAlgorithm, new DerOctetString(new DerSequence(DerInteger.ValueOf(1), DerInteger.ValueOf(1)).GetEncoded()));
        byte[] container = new ContentInfo(PkcsObjectIdentifiers.SignedData,
            new SignedData(DerInteger.ValueOf(1), new DerSet(digestAlgorithm),
                new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(new byte[] { 42 })),
                new BerSet(certificate.CertificateStructure, unrelated.CertificateStructure), null, new DerSet(signer))).GetEncoded();
        // The old binding parser selects the first certificate; Windows' compatibility loader selects the signer.
        Assert.Equal(certificate.GetEncoded(), new X509CertificateParser().ReadCertificate(container).GetEncoded());
#if !NET10_0_OR_GREATER
        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) {
            using var loaded = Helpers.CertificateLoaderCompat.LoadCertificate(container);
            Assert.Equal(unrelated.GetEncoded(), loaded.RawData);
        }
#endif
        return container;
    }

    private static byte[] Hash(byte[] data) {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(data);
    }

    private static string Hex(byte[] data) => BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CompleteDecoding_BindsPrecertificateNamesToLoggedTbs(bool dedicatedSigner, bool isStatic) {
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
        // Opaque extensions remain in the signed leaf and recovery evidence; entry 1
        // also checks that recovery encodes the slice rather than the containing tile.
        byte[] leaf = new byte[] {0,0, 0,0,0,0,0,0,0,1, 0,1}.Concat(issuerHash).Concat(Vector(tbs)).Concat(new byte[] {0,3,0xA1,0xB2,0xC3}).ToArray();
        byte[] chain = dedicatedSigner ? Vector(signer.GetEncoded()).Concat(Vector(root.GetEncoded())).ToArray() : Vector(root.GetEncoded());
        byte[] fingerprints = dedicatedSigner ? Hash(signer.GetEncoded()).Concat(Hash(root.GetEncoded())).ToArray() : Array.Empty<byte>();
        byte[] StaticEntry(byte[] der) => leaf.Skip(2).Concat(Vector(der))
            .Concat(new byte[] { (byte)(fingerprints.Length >> 8), (byte)fingerprints.Length }).Concat(fingerprints).ToArray();
        byte[] StaticTile(byte[] der) {
            byte[] precedingEntry = StaticEntry(der);
            precedingEntry[7] = 2;
            return precedingEntry.Concat(StaticEntry(der)).ToArray();
        }
        CtLogIngestionClient SelectedClient(byte[] der) => isStatic ? new CtLogIngestionClient {
            SendOverride = (message, _) => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) {
                Content = new ByteArrayContent(message.RequestUri!.AbsolutePath.Contains("/issuer/")
                    ? (message.RequestUri.AbsolutePath.EndsWith(Hex(Hash(signer.GetEncoded()))) ? signer.GetEncoded() : root.GetEncoded())
                    : StaticTile(der))
            })
        } : Client(leaf, Vector(der).Concat(Vector(chain)).ToArray());
        CtLogIngestionBatchRequest request = isStatic ? new CtLogIngestionBatchRequest {
            LogUrl = "https://ct.example.test/binding/", MonitoringUrl = "https://ct.example.test/binding/", ApiKind = CtLogApiKind.StaticCt,
            StartIndex = 1, BatchSize = 1, KnownTreeSize = 2, RequireCompleteDecoding = true
        } : Request();
        CtLogIngestionBatch batch = await SelectedClient(pre.GetEncoded()).ReadBatchAsync(request);
        CtLogIngestionEntry entry = Assert.Single(batch.Entries);
        Assert.Equal(CtLogEntryType.Precertificate, entry.EntryType);
        Assert.Contains("login.example.test", entry.Certificate.DnsNames);
        Assert.Equal(pre.GetEncoded(), entry.Certificate.CertificateDer);
        Assert.Empty(batch.Diagnostics);

        // The extra data is outside the Merkle leaf. Altering it must not introduce unrelated names.
        X509Certificate altered = Certificate(new X509Name("CN=unrelated.example.test"), dedicatedSigner ? signerName : rootName,
            leafKey, dedicatedSigner ? signerKey : rootKey, poison: true, leafAuthority: dedicatedSigner ? (byte)2 : (byte)1);
        byte[] alteredExtra = Vector(altered.GetEncoded()).Concat(Vector(chain)).ToArray();
        byte[] alteredDer = altered.GetEncoded();
        CtEntryDecodingException error = await Assert.ThrowsAsync<CtEntryDecodingException>(() => SelectedClient(alteredDer).ReadBatchAsync(request));
        Assert.Equal(isStatic ? 1 : 0, error.EntryIndex);
        Assert.Equal(Convert.ToBase64String(leaf), error.Payload.LeafInputBase64);
        Assert.Equal(Convert.ToBase64String(isStatic ? Vector(alteredDer).Concat(new byte[3]).ToArray() : alteredExtra), error.Payload.ExtraDataBase64);
        Assert.Equal(isStatic ? Convert.ToBase64String(StaticEntry(alteredDer)) : null, error.StaticTileEntryBase64);
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
        AsymmetricCipherKeyPair signingKey, bool ca = false, bool ctSigner = false, bool poison = false, byte leafAuthority = 1, int paddingBytes = 0) {
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
        if (paddingBytes > 0) generator.AddExtension(new DerObjectIdentifier("1.2.3.4.5"), false, new DerOctetString(new byte[paddingBytes]));
        return generator.Generate(new Asn1SignatureFactory("SHA256withECDSA", signingKey.Private));
    }
}
