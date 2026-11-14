using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DomainDetective.Tests;

public sealed class TestCtLogIntegrity {
    [Fact]
    public async Task StaticBatch_VerifiesGrowthAcrossDataAndHashTileBoundaries() {
        var fixture = new LogFixture(false, true, leafCount: 300);
        var previous = new CtSignedTreeHead(257, DateTimeOffset.UtcNow) {RootHashBase64=Convert.ToBase64String(fixture.Root(0,257))};
        CtLogIngestionBatch batch = await fixture.Client().ReadBatchAsync(fixture.Request(previous,start:254,batchSize:5));
        Assert.Equal(300,batch.VerifiedTreeHead!.TreeSize);
        Assert.Equal(254,batch.StartIndex);
        Assert.Equal(258,batch.EndIndex);
        Assert.Contains(1,fixture.HashTileLevels);
        fixture.TamperMiddleLeaf=true;
        fixture.TamperLeafIndex=255;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>fixture.Client().ReadBatchAsync(fixture.Request(previous,start:254,batchSize:5)));
    }

    [Fact]
    public async Task RfcEntries_HonorCancellationAfterAnOverrideReturnsItsResponse() {
        using var cancellation = new CancellationTokenSource();
        var client = new CtLogIngestionClient { HttpGetOverride = (_,_) => {
            cancellation.Cancel();
            return Task.FromResult("{\"entries\":[null]}");
        }};
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>client.GetEntriesAsync(
            "https://ct.example.test/",0,0,TimeSpan.FromSeconds(5),cancellation.Token));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RfcBatch_VerifiesPinnedSignatureAndAllRangeLeaves(bool rsa) {
        var fixture = new LogFixture(rsa);
        var client = fixture.Client();
        CtLogIngestionBatch batch = await client.ReadBatchAsync(fixture.Request());
        Assert.Equal(7, batch.TreeSize);
        Assert.Equal(1, batch.StartIndex);
        Assert.Equal(3, batch.EndIndex);
        Assert.Equal(Convert.ToBase64String(fixture.Root(0, 7)), batch.VerifiedTreeHead!.RootHashBase64);
        Assert.Equal(2, fixture.AuditCalls);
        // Deliberately minimal certificates are undecodable, but every raw leaf still has an inclusion proof.
        Assert.Equal(3, batch.Diagnostics.Count);

        fixture.TamperMiddleLeaf = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ReadBatchAsync(fixture.Request()));
    }

    [Fact]
    public async Task RfcTree_RejectsKeyMismatchInvalidSignatureAndChangedRoot() {
        var fixture = new LogFixture(false);
        var client = fixture.Client();
        var wrongKey = new CtLogDescriptor { Url = fixture.Log.Url, PublicKey = fixture.Log.PublicKey, LogId = Convert.ToBase64String(new byte[32]) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetVerifiedSignedTreeHeadAsync(wrongKey, null, TimeSpan.FromSeconds(5)));
        Assert.Equal(0, fixture.HeadCalls);
        fixture.BadSignature = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetVerifiedSignedTreeHeadAsync(fixture.Log, null, TimeSpan.FromSeconds(5)));
        fixture.BadSignature = false;
        CtSignedTreeHead verified = await client.GetVerifiedSignedTreeHeadAsync(fixture.Log, null, TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetVerifiedSignedTreeHeadAsync(fixture.Log,
            verified with { RootHashBase64 = Convert.ToBase64String(new byte[32]) }, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task RfcTree_RequiresValidConsistencyFromPreviousDurableHead() {
        var fixture = new LogFixture(false);
        var previous = new CtSignedTreeHead(3, DateTimeOffset.UtcNow) { RootHashBase64 = Convert.ToBase64String(fixture.Root(0, 3)) };
        CtSignedTreeHead head = await fixture.Client().GetVerifiedSignedTreeHeadAsync(fixture.Log, previous, TimeSpan.FromSeconds(5));
        Assert.Equal(7, head.TreeSize);
        fixture.BadConsistency = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Client().GetVerifiedSignedTreeHeadAsync(fixture.Log, previous, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task StaticBatch_VerifiesCheckpointRangeAndGrowthUsingHashTiles() {
        var fixture = new LogFixture(false, true);
        var previous = new CtSignedTreeHead(3, DateTimeOffset.UtcNow) { RootHashBase64 = Convert.ToBase64String(fixture.Root(0, 3)) };
        var request = fixture.Request(previous);
        CtLogIngestionBatch batch = await fixture.Client().ReadBatchAsync(request);
        Assert.Equal(7, batch.VerifiedTreeHead!.TreeSize);
        Assert.Equal(Convert.ToBase64String(fixture.Root(0, 7)), batch.VerifiedTreeHead.RootHashBase64);
        Assert.Equal(3, batch.Diagnostics.Count);
        Assert.True(fixture.HashTileCalls > 0);
        fixture.TamperMiddleLeaf = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Client().ReadBatchAsync(request));
        fixture.TamperMiddleLeaf = false;
        fixture.BadSignature = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Client().ReadBatchAsync(request));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteDecoding_ReturnsProvenUnparseableEntriesWithTheirRawPayload(bool isStatic) {
        var fixture = new LogFixture(false, isStatic);
        CtLogIngestionBatch batch = await fixture.Client().ReadBatchAsync(fixture.Request(complete: true));
        Assert.Empty(batch.Entries);
        Assert.Equal(new long[] { 1, 2, 3 }, batch.UndecodableEntries.Select(entry => entry.EntryIndex));
        Assert.Equal(3, batch.EndIndex);
        Assert.Equal(Convert.ToBase64String(fixture.Leaves[1]), batch.UndecodableEntries[0].Payload.LeafInputBase64);
        Assert.Equal(isStatic, batch.UndecodableEntries[0].StaticTileEntryBase64 != null);
        Assert.NotEmpty(batch.UndecodableEntries[0].Reason);

        fixture.TamperMiddleLeaf = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Client().ReadBatchAsync(fixture.Request(complete: true)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OlderSignedHead_IsProvenAsPrefixAndTheLargerVerifiedHeadIsKept(bool isStatic) {
        var fixture = new LogFixture(false, isStatic) { HeadSize = 3 };
        var previous = new CtSignedTreeHead(7, DateTimeOffset.UtcNow) { RootHashBase64 = Convert.ToBase64String(fixture.Root(0, 7)) };
        CtSignedTreeHead head = await fixture.Client().GetVerifiedSignedTreeHeadAsync(fixture.Log, previous, TimeSpan.FromSeconds(5));
        Assert.Same(previous, head);

        var forked = previous with { RootHashBase64 = Convert.ToBase64String(new byte[32]) };
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Client().GetVerifiedSignedTreeHeadAsync(fixture.Log, forked, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task LoggedCertificatesRejectedByStrictParsers_KeepTheirNamesAndAdvance() {
        // GoDaddy Aquamarine2026h2 #23760025 (notBefore in year 1, rejected by the Windows loader) and Sectigo
        // Elephant2027h2 #3554 (BER BOOLEAN in the outer signature algorithm) each stalled verified ingestion.
        byte[] godaddyEntry = Convert.FromBase64String(GoDaddyStaticEntry);
        var staticClient = new CtLogIngestionClient { SendOverride = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(godaddyEntry) }) };
        CtLogIngestionBatch staticBatch = await staticClient.ReadBatchAsync(new CtLogIngestionBatchRequest {
            LogUrl = "https://ct.example.test/godaddy/", MonitoringUrl = "https://ct.example.test/godaddy/", ApiKind = CtLogApiKind.StaticCt,
            StartIndex = 0, BatchSize = 1, KnownTreeSize = 1, RequireCompleteDecoding = true
        });
        CtCertificateRecord godaddy = Assert.Single(staticBatch.Entries).Certificate;
        Assert.Equal(new[] { "7ac2e92b4653cc4ab1879a60.Shelikhoo.kkdev.org.invalid" }, godaddy.DnsNames);

        var rfcClient = new CtLogIngestionClient { HttpGetOverride = (_, _) => Task.FromResult(JsonSerializer.Serialize(new {
            entries = new[] { new { leaf_input = SectigoLeaf, extra_data = "" } } })) };
        CtLogIngestionBatch rfcBatch = await rfcClient.ReadBatchAsync(new CtLogIngestionBatchRequest {
            LogUrl = "https://ct.example.test/sectigo/", StartIndex = 0, BatchSize = 1, KnownTreeSize = 1, RequireCompleteDecoding = true
        });
        CtCertificateRecord sectigo = Assert.Single(rfcBatch.Entries).Certificate;
        Assert.True(sectigo.IsLenientlyParsed);
        Assert.Same(sectigo, sectigo.EnsureFullDetails());
        Assert.Empty(rfcBatch.UndecodableEntries);
    }

    private const string GoDaddyStaticEntry = "AAABoWCS/PUAAAACXjCCAlowggHgoAMCAQICFHiJNzd8C9fcD3GSpPl57ho+0dIqMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwIBgPMDAwMTAxMDEwMDAwMDBaFw0yNjEyMzEyMzU5NTlaMD8xPTA7BgNVBAMMNDdhYzJlOTJiNDY1M2NjNGFiMTg3OWE2MC5TaGVsaWtob28ua2tkZXYub3JnLmludmFsaWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTTqHz9/zr87hROZmWIAoFa9o3enH7oNnnZTkAhC5aWKTFmYCpgpjm26mOgpl+u2fUX/V3BlacgOSvRuThsGqIo4G3MIG0MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMD8GA1UdEQQ4MDaCNDdhYzJlOTJiNDY1M2NjNGFiMTg3OWE2MC5TaGVsaWtob28ua2tkZXYub3JnLmludmFsaWQwHQYDVR0OBBYEFGzNi/sOh5DQeg3H1yjbleVox5JpMB8GA1UdIwQYMBaAFOIeL+ccGTkOVUtiwSAkVzUkiiUUMAoGCCqGSM49BAMDA2gAMGUCMHEOlmDi4YHxUiK+pp+ZvGp+IuNC6V+fSm/7o3sWmpZhW9/XWT5LGV/Nxp2+XZUcLwIxALIs/SBWCF7BFkUSqPZ64QVI5miaC/ZKF+iGEMuSa0q8rJ4Y6yi8uQFs1G7UQtp99QAIAAAFAAFqjJkAYELErM0SxPWVl5JeGginqQECYIVDgJMI1Q7EJ+EYuhSTMJQCV5IDmmivblU2hkEL2rfA1KNrkITLpkIC411uu92Goey6CJxKjTu+JzTGEro0HYE+BDz56KhizVxXo2u+aw==";
    private const string SectigoLeaf = "AAAAAAGXUCMW2QAAAASzMIIErzCCA5agAwIBAgIQBYAmfwbylVM0jhwYWl7uLjANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBDQTAeFw0xNzEyMDgxMjI4MjZaFw0yNzEyMDgxMjI4MjZaMHIxCzAJBgNVBAYTAkNOMSUwIwYDVQQKExxUcnVzdEFzaWEgVGVjaG5vbG9naWVzLCBJbmMuMR0wGwYDVQQLExREb21haW4gVmFsaWRhdGVkIFNTTDEdMBsGA1UEAxMUVHJ1c3RBc2lhIFRMUyBSU0EgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgWa9X+ph+wAm8Yh1Fk1MjKbQ5QwBOOKVaZR/OfCh+F6f93u7vZHGcUU/lvVGgUQnbzJhR1UV2epJae+m7cxnXIKdD0/VS9btAgwJszGFvwoqXeaCqFoP71wPmXjjUwLT70+qvX4hdyYfOJcjeTz5QKtg8zQwxaK9x4JT9CoOmoVdVhEBAiD3DwR5fFgOHDwwGxdJWVBvktnoAzjdTLXDdbSVC5jZ0u8oq9BiTDv7jAlsB5F8aZgvSZDOQeFrwaOTbKWSEInEhnchKZTD1dz6aBlk1xGEI5PZWAnVAba/ofH33ktymaTDsE6xRDnW97pDkimCRak6CEbfe3dXw6OV5AgMBAAGjggFPMIIBSzAdBgNVHQ4EFgQUf9OZ86BHDjEAVlYijrfMnt3KAYowHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgEwDgYJKoZIhvcNAQELAQGwA4IBAQCt3VTo+XZb+DMytott95Q2L8id7JRWNl9hyk2BrXvJ2yuouf37AyJjGIoQJKelWjWP3p/FmeanK0D1S7iayQ0l09ODZzHmTkA1KI/zRwJnXwgQf4dW2eThiukn9YeWMf+cEeH901KD4BpZ1OxLjyEizXTEYg6157XCJgwIkb5IeRibh+GAlROlxJ7amjSIBpEcMSkoJ1NyHd4rhW1vRVEPUKrW9Rl/dQCe4uNed04pBoGAncGJAVEQ/IElXvDgHKOiH2TmLf0xMIotSL4tQqp7lJVqbBdS3UDSHX21t00ntAYUGu4n21SH7z1h2Drt65INWXjKOl0VPQeJ+VciWEZhAAA=";

    [Fact]
    public async Task RfcMalformedEntries_KeepTheirPositionsInsteadOfShiftingLaterIndices() {
        var client = new CtLogIngestionClient { HttpGetOverride = (_, _) => Task.FromResult("{\"entries\":[null,{}, {\"leaf_input\":\"AQ==\",\"extra_data\":\"\"}]}") };
        IReadOnlyList<RawCtEntryPayload> entries = await client.GetEntriesAsync("https://ct.example.test/", 10, 12, TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Equal(3, entries.Count);
        Assert.Empty(entries[0].LeafInputBase64);
        Assert.Empty(entries[1].LeafInputBase64);
        Assert.Equal("AQ==", entries[2].LeafInputBase64);
    }

    [Fact]
    public void ConsistencyProofs_CoverNonPowerOfTwoGrowthAndRejectAlteration() {
        var fixture = new LogFixture(false);
        for (int first = 1; first < 7; first++) {
            var proof = fixture.Consistency(first, 7);
            CtMerkleTree.VerifyConsistency(first, 7, fixture.Root(0, first), fixture.Root(0, 7), proof);
            var corrupt = proof.Select(hash => (byte[])hash.Clone()).ToArray();
            corrupt[0][0] ^= 1;
            Assert.Throws<InvalidOperationException>(() => CtMerkleTree.VerifyConsistency(first, 7, fixture.Root(0, first), fixture.Root(0, 7), corrupt));
        }
    }

    private sealed class LogFixture {
        private readonly AsymmetricCipherKeyPair _keys;
        private readonly bool _rsa;
        private readonly bool _static;
        public byte[][] Leaves { get; }
        public CtLogDescriptor Log { get; }
        public bool TamperMiddleLeaf { get; set; }
        public int TamperLeafIndex { get; set; } = 2;
        public bool BadSignature { get; set; }
        public bool BadConsistency { get; set; }
        public int? HeadSize { get; set; }
        public int AuditCalls { get; private set; }
        public int HeadCalls { get; private set; }
        public int HashTileCalls { get; private set; }
        public HashSet<int> HashTileLevels { get; } = new();

        public LogFixture(bool rsa, bool isStatic = false, int leafCount = 7) {
            _rsa = rsa;
            _static = isStatic;
            if (rsa) {
                var generator = new RsaKeyPairGenerator();
                generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
                _keys = generator.GenerateKeyPair();
            } else {
                var generator = new ECKeyPairGenerator();
                var curve = SecNamedCurves.GetByName("secp256r1");
                generator.Init(new ECKeyGenerationParameters(new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H), new SecureRandom()));
                _keys = generator.GenerateKeyPair();
            }
            byte[] key = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_keys.Public).GetDerEncoded();
            Log = new CtLogDescriptor {
                Url = "https://ct.example.test/log/", SubmissionUrl = "https://ct.example.test/log/", MonitoringUrl = "https://tiles.example.test/",
                ApiKind = isStatic ? CtLogApiKind.StaticCt : CtLogApiKind.Rfc6962,
                PublicKey = Convert.ToBase64String(key), LogId = Convert.ToBase64String(Sha(key))
            };
            // v1 timestamped X509 leaves with a tiny invalid DER certificate, a valid TLS vector and no extensions.
            Leaves = Enumerable.Range(0, leafCount).Select(i => new byte[] { 0,0, 0,0,0,0,0,0,0,(byte)(i+1), 0,0, 0,0,2, 0x30,0, 0,0 }).ToArray();
        }

        public CtLogIngestionBatchRequest Request(CtSignedTreeHead? previous = null, bool complete = false, long start = 1, int batchSize = 3) => new() {
            LogUrl = Log.Url, SubmissionUrl = Log.SubmissionUrl, MonitoringUrl = Log.MonitoringUrl, ApiKind = Log.ApiKind,
            PublicKey = Log.PublicKey, LogId = Log.LogId, RequireIntegrityVerification = true, PreviousTreeHead = previous,
            RequireCompleteDecoding = complete, StartIndex = start, BatchSize = batchSize, KnownTreeSize = 99
        };

        public CtLogIngestionClient Client() => new() { SendOverride = (request, _) => Task.FromResult(Respond(request.RequestUri!)) };

        private HttpResponseMessage Respond(Uri uri) {
            string path = uri.AbsolutePath;
            if (path.EndsWith("get-sth")) { HeadCalls++; return Json(new { tree_size = Size, timestamp = 123L, sha256_root_hash = Convert.ToBase64String(Root(0, Size)), tree_head_signature = Convert.ToBase64String(Signature()) }); }
            if (path.EndsWith("get-entries")) {
                var leaves = Leaves.Skip(1).Take(3).Select(leaf => (byte[])leaf.Clone()).ToArray();
                if (TamperMiddleLeaf) leaves[1][9] ^= 1;
                return Json(new { entries = leaves.Select(leaf => new { leaf_input = Convert.ToBase64String(leaf), extra_data = "" }) });
            }
            if (path.EndsWith("get-entry-and-proof")) {
                AuditCalls++;
                int index = int.Parse(uri.Query.TrimStart('?').Split('&')[0].Split('=')[1]);
                return Json(new { leaf_input = Convert.ToBase64String(Leaves[index]), extra_data = "", audit_path = Audit(index, 0, 7).Select(Convert.ToBase64String) });
            }
            if (path.EndsWith("get-sth-consistency")) {
                int[] sizes = uri.Query.TrimStart('?').Split('&').Select(part => int.Parse(part.Split('=')[1])).ToArray();
                var proof = Consistency(sizes[0], sizes[1]).ToArray();
                if (BadConsistency) proof[0] = new byte[32];
                return Json(new { consistency = proof.Select(Convert.ToBase64String) });
            }
            if (path.EndsWith("checkpoint")) {
                HeadCalls++;
                string origin = "ct.example.test/log";
                byte[] keyIdentity = Encoding.UTF8.GetBytes(origin + "\n").Concat(new byte[] {5}).Concat(Convert.FromBase64String(Log.LogId!)).ToArray();
                byte[] signature = Sha(keyIdentity).Take(4).Concat(UInt64(123)).Concat(Signature()).ToArray();
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"{origin}\n{Size}\n{Convert.ToBase64String(Root(0,Size))}\n\n\u2014 {origin} {Convert.ToBase64String(signature)}\n") };
            }
            if (path.Contains("tile/data/")) {
                byte[][] leaves = Leaves.Select(leaf => (byte[])leaf.Clone()).ToArray();
                if (TamperMiddleLeaf) leaves[TamperLeafIndex][9] ^= 1;
                string suffix=path.Substring(path.IndexOf("tile/data/",StringComparison.Ordinal)+10);
                int tileIndex=int.Parse(suffix.Split('.')[0]);
                int width=suffix.Contains(".p/") ? int.Parse(suffix.Split('/').Last()) : 256;
                return Bytes(leaves.Skip(tileIndex*256).Take(width).SelectMany(leaf => leaf.Skip(2).Concat(new byte[] {0,0})).ToArray());
            }
            if (path.Contains("tile/")) {
                HashTileCalls++;
                string[] parts=path.Substring(path.IndexOf("tile/",StringComparison.Ordinal)+5).Split('/');
                int level=int.Parse(parts[0]),tileIndex=int.Parse(parts[1].Split('.')[0]);
                HashTileLevels.Add(level);
                int nodeSize=(int)Math.Pow(256,level);
                int width=parts[1].Contains(".p") ? int.Parse(parts.Last()) : 256;
                return Bytes(Enumerable.Range(0,width).SelectMany(i=>Root((tileIndex*256+i)*nodeSize,nodeSize)).ToArray());
            }
            throw new InvalidOperationException("Unexpected CT fixture URL: " + uri);
        }

        private byte[] Signature() {
            byte[] message = new byte[] {0,1}.Concat(UInt64(123)).Concat(UInt64((ulong)Size)).Concat(Root(0,Size)).ToArray();
            var signer = SignerUtilities.GetSigner(_rsa ? "SHA256withRSA" : "SHA256withECDSA");
            signer.Init(true, _keys.Private);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();
            if (BadSignature) signature[signature.Length - 1] ^= 1;
            return new byte[] {4, (byte)(_rsa ? 1 : 3), (byte)(signature.Length >> 8), (byte)signature.Length}.Concat(signature).ToArray();
        }

        private int Size => HeadSize ?? Leaves.Length;

        public byte[] Root(int start, int size) {
            if (size == 1) return HashLeaf(Leaves[start]);
            int split = Split(size);
            return HashNode(Root(start,split),Root(start+split,size-split));
        }
        private IReadOnlyList<byte[]> Audit(int index, int start, int size) {
            if (size == 1) return Array.Empty<byte[]>();
            int split = Split(size);
            return index < start + split
                ? Audit(index,start,split).Concat(new[] {Root(start+split,size-split)}).ToArray()
                : Audit(index,start+split,size-split).Concat(new[] {Root(start,split)}).ToArray();
        }
        public IReadOnlyList<byte[]> Consistency(int first, int second) => Subproof(first,second,0,true);
        private IReadOnlyList<byte[]> Subproof(int first, int second, int start, bool complete) {
            if (first == second) return complete ? Array.Empty<byte[]>() : new[] {Root(start,second)};
            int split = Split(second);
            return first <= split
                ? Subproof(first,split,start,complete).Concat(new[] {Root(start+split,second-split)}).ToArray()
                : Subproof(first-split,second-split,start+split,false).Concat(new[] {Root(start,split)}).ToArray();
        }
        private static int Split(int size) => (int)Math.Pow(2, Math.Ceiling(Math.Log(size,2))-1);
        private static byte[] UInt64(ulong value) => Enumerable.Range(0,8).Select(i => (byte)(value >> ((7-i)*8))).ToArray();
        private static byte[] Sha(byte[] data) { using var sha = SHA256.Create(); return sha.ComputeHash(data); }
        private static byte[] HashLeaf(byte[] leaf) => Sha(new byte[] {0}.Concat(leaf).ToArray());
        private static byte[] HashNode(byte[] left, byte[] right) => Sha(new byte[] {1}.Concat(left).Concat(right).ToArray());
        private static HttpResponseMessage Json(object data) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(data)) };
        private static HttpResponseMessage Bytes(byte[] data) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(data) };
    }
}
