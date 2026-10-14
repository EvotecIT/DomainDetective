using System;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace DomainDetective;

/// <summary>Authenticates certificate-specific revocation evidence; it does not establish system chain trust.</summary>
internal static class CertificateRevocationEvidence {
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumOcspAgeWithoutNextUpdate = TimeSpan.FromHours(24);

    internal static bool? OcspStatus(byte[] bytes, X509Certificate leaf, X509Certificate issuer, DateTime nowUtc) {
        try {
            if (!IsIssuer(leaf, issuer)) return null;
            _ = Asn1Object.FromByteArray(bytes);
            var response = new OcspResp(bytes);
            if (response.Status != OcspRespStatus.Successful || response.GetResponseObject() is not BasicOcspResp basic) return null;
            if (basic.GetCriticalExtensionOids()?.Count > 0 || basic.ProducedAt > nowUtc + ClockSkew) return null;
            var matches = basic.Responses.Where(r => r.GetCertID().SerialNumber.Equals(leaf.SerialNumber) && r.GetCertID().MatchesIssuer(issuer)).ToArray();
            if (matches.Length != 1) return null;
            var single = matches[0];
            if (single.GetCriticalExtensionOids()?.Count > 0 || single.ThisUpdate > nowUtc + ClockSkew || basic.ProducedAt < single.ThisUpdate - ClockSkew) return null;
            if (single.NextUpdate is DateTime next) {
                if (next < single.ThisUpdate || next < nowUtc - ClockSkew) return null;
            } else if (single.ThisUpdate < nowUtc - MaximumOcspAgeWithoutNextUpdate) return null;
            bool authenticated = new[] { issuer }.Concat(basic.GetCerts()).Any(signer => IsAuthorizedOcspSigner(signer, issuer, basic, nowUtc));
            if (!authenticated) return null;
            var status = single.GetCertStatus();
            if (status is RevokedStatus revoked) return revoked.RevocationTime <= nowUtc + ClockSkew ? true : null;
            return status == null ? false : null;
        } catch (Exception) {
            return null;
        }
    }

    internal static bool? CrlStatus(byte[] bytes, X509Certificate leaf, X509Certificate issuer, DateTime nowUtc, string? distributionPointUrl = null) {
        try {
            if (!IsIssuer(leaf, issuer)) return null;
            var distributionPoints = leaf.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (distributionPoints != null) {
                var points = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(distributionPoints.GetOctets())).GetDistributionPoints();
                // A complete direct point covers all reasons independently of other points.
                // Without the selected point, restricted/indirect evidence remains ambiguous.
                if (distributionPointUrl == null) {
                    if (points.Any(point => point.Reasons != null || point.CrlIssuer != null)) return null;
                } else if (!CompleteCrlUrls(leaf).Contains(distributionPointUrl, StringComparer.Ordinal)) {
                    return null;
                }
            }
            _ = Asn1Object.FromByteArray(bytes);
            var crl = new X509CrlParser().ReadCrl(bytes);
            if (!crl.IssuerDN.Equivalent(issuer.SubjectDN) || crl.ThisUpdate > nowUtc + ClockSkew
                || crl.NextUpdate is not DateTime next || next < nowUtc - ClockSkew || next < crl.ThisUpdate) return null;
            var usage = issuer.GetKeyUsage();
            if (usage != null && (usage.Length <= 6 || !usage[6])) return null;
            // Delta, indirect and restricted distribution-point CRLs require scope/base processing.
            // Until that evidence is available, neither absence nor membership is a complete verdict.
            if (crl.GetExtensionValue(X509Extensions.DeltaCrlIndicator) != null || crl.GetExtensionValue(X509Extensions.IssuingDistributionPoint) != null
                || crl.GetCriticalExtensionOids()?.Count > 0) return null;
            crl.Verify(issuer.GetPublicKey());
            var entries = crl.GetRevokedCertificates();
            if (entries != null && entries.Any(entry => entry.GetExtensionValue(X509Extensions.CertificateIssuer) != null || entry.GetCriticalExtensionOids()?.Count > 0)) return null;
            var revoked = crl.GetRevokedCertificate(leaf.SerialNumber);
            return revoked == null ? false : revoked.RevocationDate <= nowUtc + ClockSkew ? true : null;
        } catch (Exception) {
            return null;
        }
    }

    /// <summary>Finds URI points whose complete direct issuer CRLs this evaluator supports.</summary>
    internal static string[] CompleteCrlUrls(X509Certificate leaf) {
        var extension = leaf.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (extension == null) return Array.Empty<string>();
        var points = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(extension.GetOctets())).GetDistributionPoints();
        return points.Where(point => point.Reasons == null && point.CrlIssuer == null
                && point.DistributionPointName?.Type == DistributionPointName.FullName)
            .SelectMany(point => GeneralNames.GetInstance(point.DistributionPointName.Name).GetNames())
            .Where(name => name.TagNo == GeneralName.UniformResourceIdentifier)
            .Select(name => Org.BouncyCastle.Asn1.DerIA5String.GetInstance(name.Name).GetString())
            .Distinct(StringComparer.Ordinal).ToArray();
    }

    private static bool IsIssuer(X509Certificate leaf, X509Certificate issuer) {
        if (!leaf.IssuerDN.Equivalent(issuer.SubjectDN)) return false;
        leaf.Verify(issuer.GetPublicKey());
        return true;
    }

    private static bool IsAuthorizedOcspSigner(X509Certificate signer, X509Certificate issuer, BasicOcspResp response, DateTime nowUtc) {
        try {
            if (!response.ResponderId.Equals(new RespID(signer.SubjectDN)) && !response.ResponderId.Equals(new RespID(signer.GetPublicKey()))) return false;
            if (!signer.IsValid(nowUtc) || !response.Verify(signer.GetPublicKey())) return false;
            if (signer.Equals(issuer)) return true;
            if (!IsIssuer(signer, issuer) || signer.GetExtendedKeyUsage()?.Contains(KeyPurposeID.id_kp_OCSPSigning) != true) return false;
            var critical = signer.GetCriticalExtensionOids();
            const string noCheckOid = "1.3.6.1.5.5.7.48.1.5";
            if (critical != null && critical.Any(oid => !oid.Equals(X509Extensions.BasicConstraints.Id)
                && !oid.Equals(X509Extensions.KeyUsage.Id) && !oid.Equals(X509Extensions.ExtendedKeyUsage.Id)
                && !oid.Equals(noCheckOid))) return false;
            var usage = signer.GetKeyUsage();
            if (usage != null && !((usage.Length > 0 && usage[0]) || (usage.Length > 1 && usage[1]))) return false;
            // Delegated signer revocation cannot be skipped unless its issuer authorized no-check.
            var noCheck = signer.GetExtensionValue(new DerObjectIdentifier(noCheckOid));
            return noCheck != null && Asn1Object.FromByteArray(noCheck.GetOctets()) is DerNull;
        } catch (Exception) {
            return false;
        }
    }
}
