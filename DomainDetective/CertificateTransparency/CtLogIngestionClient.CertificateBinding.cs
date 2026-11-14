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
    private Task<X509Certificate?> VerifyCertificateBindingAsync(RawCtEntryPayload payload, byte[] certificateDer, string? monitoringUrl,
        byte[]? staticIssuerFingerprints, TimeSpan timeout, CancellationToken cancellationToken,
        Dictionary<string, byte[]>? issuerCache = null) =>
        VerifyCertificateBindingAsync(DecodeRequiredBase64(payload.LeafInputBase64, "entry leaf"), payload.ExtraDataBase64,
            certificateDer, monitoringUrl, staticIssuerFingerprints, timeout, cancellationToken, issuerCache);

    // Static tiles already contain the leaf bytes; Base64 is needed only for RFC payloads and failure diagnostics.
    private async Task<X509Certificate?> VerifyCertificateBindingAsync(byte[] leaf, string extraDataBase64, byte[] certificateDer, string? monitoringUrl,
        byte[]? staticIssuerFingerprints, TimeSpan timeout, CancellationToken cancellationToken,
        Dictionary<string, byte[]>? issuerCache = null) {
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
            return null;
        }
        X509Certificate certificate;
        try {
            certificate = CtCertificateDer.Parse(certificateDer);
        } catch (System.Security.Cryptography.CryptographicException) {
            try {
                certificate = CtCertificateDer.ParseLenient(certificateDer);
            } catch (System.Security.Cryptography.CryptographicException ex) {
                throw new EntryCertificateParsingException(ex);
            }
        }
        if (CtMerkleTree.Equal(CtCertificateDer.NormalizePrecertificateTbs(certificate, null), signedCertificate)) return certificate;

        // RFC6962 also permits a dedicated precertificate signer. Only this uncommon path needs issuer certificates.
        IReadOnlyList<byte[]> issuers;
        if (monitoringUrl == null) issuers = ParsePrecertificateIssuers(DecodeRequiredBase64(extraDataBase64, "precertificate extra data"));
        else {
            if (staticIssuerFingerprints == null || staticIssuerFingerprints.Length < 64)
                throw new InvalidOperationException("Static CT precertificate signer chain is incomplete.");
            var fetched = new List<byte[]>();
            for (int i = 0; i < 2; i++) {
                byte[] fingerprint = new byte[32];
                Buffer.BlockCopy(staticIssuerFingerprints, i * 32, fingerprint, 0, 32);
                string hex = BitConverter.ToString(fingerprint).Replace("-", "").ToLowerInvariant();
                string issuerUrl = CombineLogUrl(monitoringUrl, "issuer/" + hex);
                byte[] issuer;
                if (issuerCache != null && issuerCache.TryGetValue(issuerUrl, out byte[]? cached)) {
                    issuer = cached;
                } else {
                    issuer = await FetchBytesAsync(issuerUrl, timeout, cancellationToken).ConfigureAwait(false);
                }
                if (!CtMerkleTree.Equal(CtMerkleTree.Hash(issuer), fingerprint)) throw new InvalidOperationException("Static CT issuer does not match its fingerprint.");
                // Retain at most 4 MiB of issuer bytes per batch. Larger issuers still undergo normal validation.
                if (issuerCache != null && issuerCache.Count < 64 && issuer.Length <= 64 * 1024) issuerCache[issuerUrl] = issuer;
                fetched.Add(issuer);
            }
            issuers = fetched;
        }
        if (issuers.Count < 2) throw new InvalidOperationException("CT precertificate signer chain is incomplete.");
        X509Certificate signer = CtCertificateDer.Parse(issuers[0]);
        X509Certificate issuerCertificate = CtCertificateDer.Parse(issuers[1]);
        if (signer.GetBasicConstraints() < 0 || signer.GetExtendedKeyUsage()?.Contains(new DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")) != true ||
            !certificate.IssuerDN.Equivalent(signer.SubjectDN) || !signer.IssuerDN.Equivalent(issuerCertificate.SubjectDN) ||
            !CtMerkleTree.Equal(CtMerkleTree.Hash(issuerCertificate.CertificateStructure.TbsCertificate.SubjectPublicKeyInfo.GetDerEncoded()), issuerKeyHash!))
            throw new InvalidOperationException("CT precertificate signer is not bound to the logged issuer key.");
        signer.Verify(issuerCertificate.GetPublicKey());
        certificate.Verify(signer.GetPublicKey());
        if (!CtMerkleTree.Equal(CtCertificateDer.NormalizePrecertificateTbs(certificate, signer), signedCertificate))
            throw new InvalidOperationException("CT precertificate extra data does not match its signed TBSCertificate.");
        return certificate;
    }

    // Only an unreadable entry certificate can be quarantined. An unreadable issuer prevents binding verification.
    private sealed class EntryCertificateParsingException : System.Security.Cryptography.CryptographicException {
        internal EntryCertificateParsingException(Exception inner) : base("CT entry certificate could not be parsed.", inner) { }
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
