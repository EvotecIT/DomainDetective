using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace DomainDetective;

public sealed partial class CtLogIngestionClient {
    // Precertificate DER lives in unauthenticated extra data. Its certificate fields must match the signed TBS.
    private async Task VerifyCertificateBindingAsync(RawCtEntryPayload payload, byte[] certificateDer, string? monitoringUrl,
        byte[]? staticIssuerFingerprints, TimeSpan timeout, CancellationToken cancellationToken) {
        byte[] leaf = DecodeRequiredBase64(payload.LeafInputBase64, "entry leaf");
        if (leaf.Length < 12 || leaf[0] != 0 || leaf[1] != 0) throw new InvalidOperationException("CT leaf has an unsupported version or type.");
        int offset = 2;
        if (!TryReadUInt64BigEndian(leaf, ref offset, out ulong timestamp) || timestamp > long.MaxValue ||
            !TryReadUInt16BigEndian(leaf, ref offset, out int type)) throw new InvalidOperationException("CT leaf header is malformed.");
        DateTimeOffset.FromUnixTimeMilliseconds((long)timestamp);
        byte[]? issuerKeyHash = null;
        if (type == PrecertEntryType) {
            if (offset + 32 > leaf.Length) throw new InvalidOperationException("CT precertificate issuer key hash is missing.");
            issuerKeyHash = new byte[32];
            Buffer.BlockCopy(leaf, offset, issuerKeyHash, 0, 32);
            offset += 32;
        } else if (type != X509EntryType) throw new InvalidOperationException("CT entry type is unsupported.");
        if (!TryReadVector24(leaf, ref offset, out byte[]? signedCertificate) || signedCertificate!.Length == 0 ||
            !TryReadVector16(leaf, ref offset, out _) || offset != leaf.Length)
            throw new InvalidOperationException("CT signed entry or extension vector is malformed.");
        if (type == X509EntryType) {
            if (!CtMerkleTree.Equal(certificateDer, signedCertificate)) throw new InvalidOperationException("CT X509 certificate does not match its signed leaf.");
            return;
        }
        var parser = new X509CertificateParser();
        X509Certificate certificate = parser.ReadCertificate(certificateDer);
        if (CtMerkleTree.Equal(NormalizePrecertificateTbs(certificate, null), signedCertificate)) return;

        // RFC6962 also permits a dedicated precertificate signer. Only this uncommon path needs issuer certificates.
        IReadOnlyList<byte[]> issuers;
        if (monitoringUrl == null) issuers = ParsePrecertificateIssuers(DecodeRequiredBase64(payload.ExtraDataBase64, "precertificate extra data"));
        else {
            if (staticIssuerFingerprints == null || staticIssuerFingerprints.Length < 64)
                throw new InvalidOperationException("Static CT precertificate signer chain is incomplete.");
            var fetched = new List<byte[]>();
            for (int i = 0; i < 2; i++) {
                byte[] fingerprint = new byte[32];
                Buffer.BlockCopy(staticIssuerFingerprints, i * 32, fingerprint, 0, 32);
                string hex = BitConverter.ToString(fingerprint).Replace("-", "").ToLowerInvariant();
                byte[] issuer = await FetchBytesAsync(CombineLogUrl(monitoringUrl, "issuer/" + hex), timeout, cancellationToken).ConfigureAwait(false);
                if (!CtMerkleTree.Equal(CtMerkleTree.Hash(issuer), fingerprint)) throw new InvalidOperationException("Static CT issuer does not match its fingerprint.");
                fetched.Add(issuer);
            }
            issuers = fetched;
        }
        if (issuers.Count < 2) throw new InvalidOperationException("CT precertificate signer chain is incomplete.");
        X509Certificate signer = parser.ReadCertificate(issuers[0]);
        X509Certificate issuerCertificate = parser.ReadCertificate(issuers[1]);
        if (signer.GetBasicConstraints() < 0 || signer.GetExtendedKeyUsage()?.Contains(new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")) != true ||
            !certificate.IssuerDN.Equivalent(signer.SubjectDN) || !signer.IssuerDN.Equivalent(issuerCertificate.SubjectDN) ||
            !CtMerkleTree.Equal(CtMerkleTree.Hash(issuerCertificate.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded()), issuerKeyHash!))
            throw new InvalidOperationException("CT precertificate signer is not bound to the logged issuer key.");
        signer.Verify(issuerCertificate.GetPublicKey());
        certificate.Verify(signer.GetPublicKey());
        if (!CtMerkleTree.Equal(NormalizePrecertificateTbs(certificate, signer), signedCertificate))
            throw new InvalidOperationException("CT precertificate extra data does not match its signed TBSCertificate.");
    }

    private static byte[] NormalizePrecertificateTbs(X509Certificate certificate, X509Certificate? signer) {
        var poison = new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.3");
        var sctList = new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.2");
        Asn1Sequence tbs = Asn1Sequence.GetInstance(certificate.CertificateStructure.TbsCertificate.ToAsn1Object());
        var fields = new Asn1EncodableVector();
        int issuerIndex = tbs[0] is Asn1TaggedObject ? 3 : 2;
        for (int i = 0; i < tbs.Count; i++) {
            if (signer != null && i == issuerIndex) { fields.Add(signer.CertificateStructure.TbsCertificate.Issuer); continue; }
            if (tbs[i] is Asn1TaggedObject tagged && tagged.TagNo == 3) {
                Asn1Sequence extensions = Asn1Sequence.GetInstance(tagged, true);
                var retained = new Asn1EncodableVector();
                foreach (Asn1Encodable encoded in extensions) {
                    Asn1Sequence extension = Asn1Sequence.GetInstance(encoded);
                    DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(extension[0]);
                    if (oid.Equals(poison) || oid.Equals(sctList)) continue;
                    if (signer != null && oid.Equals(X509Extensions.AuthorityKeyIdentifier)) {
                        X509Extension? replacement = signer.CertificateStructure.TbsCertificate.Extensions?.GetExtension(oid);
                        if (replacement == null) throw new InvalidOperationException("CT precertificate signer is missing Authority Key Identifier.");
                        var values = new Asn1EncodableVector();
                        values.Add(oid);
                        if (replacement.IsCritical) values.Add(DerBoolean.True);
                        values.Add(replacement.Value);
                        retained.Add(new DerSequence(values));
                    } else retained.Add(extension);
                }
                if (retained.Count > 0) fields.Add(new DerTaggedObject(true, 3, new DerSequence(retained)));
            } else fields.Add(tbs[i]);
        }
        return new DerSequence(fields).GetDerEncoded();
    }

    private static IReadOnlyList<byte[]> ParsePrecertificateIssuers(byte[] extraData) {
        int offset = 0;
        if (!TryReadVector24(extraData, ref offset, out _) || !TryReadVector24(extraData, ref offset, out byte[]? chain) || offset != extraData.Length)
            throw new InvalidOperationException("CT precertificate chain is malformed.");
        var issuers = new List<byte[]>();
        int chainOffset = 0;
        while (chainOffset < chain!.Length && issuers.Count < 2) {
            if (!TryReadVector24(chain, ref chainOffset, out byte[]? issuer) || issuer!.Length == 0)
                throw new InvalidOperationException("CT precertificate issuer vector is malformed.");
            issuers.Add(issuer);
        }
        return issuers;
    }
}
