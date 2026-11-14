using System;
using System.Security.Cryptography;
using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace DomainDetective;

/// <summary>Parses exactly one DER certificate so CT binding and platform loading use the same object.</summary>
internal static class CtCertificateDer {
    private static readonly DerObjectIdentifier PoisonOid = new("1.3.6.1.4.1.11129.2.4.3");
    private static readonly DerObjectIdentifier SctListOid = new("1.3.6.1.4.1.11129.2.4.2");

    internal static X509Certificate Parse(byte[] der) {
        X509Certificate certificate;
        try {
            // FromByteArray rejects trailing ASN.1 objects; GetInstance rejects certificate containers.
            certificate = new X509Certificate(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(der)));
        } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
            throw new CryptographicException("CT certificate bytes must contain exactly one DER-encoded X.509 certificate.", ex);
        }

        ValidateEncoding(der, certificate);
        return certificate;
    }

    /// <summary>Checks that a previously parsed certificate still represents exactly the supplied DER.</summary>
    internal static void ValidateEncoding(byte[] der, X509Certificate certificate) {
        if (!CtMerkleTree.Equal(der, certificate.GetEncoded())) {
            throw new CryptographicException("CT certificate bytes must use DER encoding without trailing data.");
        }
    }

    /// <summary>
    /// Builds the RFC6962 precertificate TBSCertificate: poison and SCT list extensions removed and, for a
    /// dedicated precertificate signer, the issuer and Authority Key Identifier taken from that signer.
    /// Without a signer, the same bytes identify a final certificate and its precertificate.
    /// </summary>
    internal static byte[] NormalizePrecertificateTbs(X509Certificate certificate, X509Certificate? signer) {
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
                    if (oid.Equals(PoisonOid) || oid.Equals(SctListOid)) continue;
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
}
