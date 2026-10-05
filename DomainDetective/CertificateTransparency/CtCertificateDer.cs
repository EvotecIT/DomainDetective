using System;
using System.Security.Cryptography;
using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace DomainDetective;

/// <summary>Parses exactly one DER certificate so CT binding and platform loading use the same object.</summary>
internal static class CtCertificateDer {
    internal static X509Certificate Parse(byte[] der) {
        X509Certificate certificate;
        try {
            // FromByteArray rejects trailing ASN.1 objects; GetInstance rejects certificate containers.
            certificate = new X509Certificate(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(der)));
        } catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) {
            throw new CryptographicException("CT certificate bytes must contain exactly one DER-encoded X.509 certificate.", ex);
        }

        if (!CtMerkleTree.Equal(der, certificate.GetEncoded())) {
            throw new CryptographicException("CT certificate bytes must use DER encoding without trailing data.");
        }

        return certificate;
    }
}
