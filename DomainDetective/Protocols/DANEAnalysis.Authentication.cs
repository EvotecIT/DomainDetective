using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace DomainDetective;

public partial class DANEAnalysis {
    /// <summary>Whether authentication was evaluated for at least one TLSA record.</summary>
    public bool AuthenticationValidationPerformed => AnalysisResults.Any(record => record.AuthenticationStatus != DaneAuthenticationStatus.NotChecked);
    /// <summary>Whether a service has failed every usable TLSA alternative.</summary>
    public bool HasAuthenticationFailures => AnalysisResults.Where(record => record.ValidDANERecord)
        .GroupBy(record => record.DomainName, StringComparer.OrdinalIgnoreCase)
        .Any(group => group.All(record => record.AuthenticationStatus == DaneAuthenticationStatus.Failed));
    /// <summary>Whether every TLSA owner with usable records has at least one authenticated association.</summary>
    public bool AllServicesAuthenticated => AnalysisResults.Any(record => record.ValidDANERecord)
        && AnalysisResults.Where(record => record.ValidDANERecord).GroupBy(record => record.DomainName, StringComparer.OrdinalIgnoreCase)
            .All(group => group.Any(record => record.AuthenticationStatus == DaneAuthenticationStatus.Authenticated));

    private static void AuthenticateCertificate(DANERecordAnalysis record, DaneCertificateEvidence evidence, X509Certificate2[] matching) {
        if (record.CertificateUsage != TlsaUsage.DaneTa && matching.Length == 0) {
            SetAuthentication(record, DaneAuthenticationStatus.Failed, "The service certificate does not match the TLSA association.");
            return;
        }
        if (record.CertificateUsage == TlsaUsage.DaneTa) {
            var parser = new X509CertificateParser();
            var anchors = matching.Select(certificate => parser.ReadCertificate(certificate.RawData)).ToList();
            if (record.SelectorField == TlsaSelector.Cert && record.MatchingTypeField == TlsaMatchingType.Full) {
                // RFC 7671 requires support for a full TA supplied only through DNS.
                anchors.Add(parser.ReadCertificate(HexToBytes(record.CertificateAssociationData)));
            }
            var leaf = parser.ReadCertificate(evidence.EndEntityCertificate!.RawData);
            var chain = evidence.CertificateChain.Select(certificate => parser.ReadCertificate(certificate.RawData)).Append(leaf).ToArray();
            bool pathValid = anchors.Any(anchor => ValidateDanePath(leaf, chain, anchor, record.SelectorField));
            if (!pathValid) {
                SetAuthentication(record, DaneAuthenticationStatus.Failed, "No valid service certificate path reaches the TLSA trust anchor.");
                return;
            }
        }
        if (record.CertificateUsage != TlsaUsage.DaneEe && evidence.HostnameMatch != true) {
            SetAuthentication(record, evidence.HostnameMatch == false ? DaneAuthenticationStatus.Failed : DaneAuthenticationStatus.Inconclusive,
                evidence.HostnameMatch == false ? "The certificate does not match the service reference name." : "The service reference name has not been checked.");
            return;
        }
        // DANE-EE authenticates the leaf directly; RFC 7671 excludes PKIX expiry and name checks.
        SetAuthentication(record, DaneAuthenticationStatus.Authenticated, "Certificate evidence satisfies the TLSA authentication requirements.");
    }

    private static bool ValidateDanePath(BcCertificate leaf, BcCertificate[] chain, BcCertificate anchor, TlsaSelector selector) {
        try {
            TrustAnchor trust = selector == TlsaSelector.Cert
                ? new TrustAnchor(anchor, anchor.GetExtensionValue(X509Extensions.NameConstraints)?.GetOctets())
                : new TrustAnchor(anchor.SubjectDN, anchor.GetPublicKey(), null);
            var parameters = new PkixBuilderParameters(new HashSet<TrustAnchor> { trust }, new X509CertStoreSelector { Certificate = leaf }) {
                // Offline diagnostic path validation does not fetch CRLs or OCSP responses.
                IsRevocationEnabled = false,
                Date = DateTime.UtcNow
            };
            parameters.AddStoreCert(CollectionUtilities.CreateStore(chain));
            var path = new PkixCertPathBuilder().Build(parameters).CertPath.Certificates;
            var keyUsage = leaf.GetKeyUsage();
            if (keyUsage != null && !keyUsage[0] && !keyUsage[2] && !keyUsage[4]) return false;
            if (selector == TlsaSelector.Cert) {
                int intermediates = path.Skip(1).Count(certificate => !certificate.SubjectDN.Equivalent(certificate.IssuerDN));
                if (anchor.GetBasicConstraints() >= 0 && intermediates > anchor.GetBasicConstraints()) return false;
                ValidateAnchorNames(anchor, path);
            }
            foreach (var certificate in path) {
                if (!AllowsTlsServer(certificate)) return false;
            }
            return selector != TlsaSelector.Cert || AllowsTlsServer(anchor);
        } catch (PkixCertPathBuilderException) {
            return false;
        } catch (PkixCertPathValidatorException) {
            return false;
        } catch (PkixNameConstraintValidatorException) {
            return false;
        }
    }

    private static void ValidateAnchorNames(BcCertificate anchor, IList<BcCertificate> path) {
        var extension = anchor.GetExtensionValue(X509Extensions.NameConstraints);
        if (extension == null) return;
        // The BC path builder processes intermediate constraints, but does not seed the
        // validator from TrustAnchor.NameConstraints. Apply these immutable Cert(0)
        // constraints to the selected path through the same BC constraint engine.
        var constraints = NameConstraints.GetInstance(extension.GetOctets());
        var validator = new PkixNameConstraintValidator();
        if (constraints.PermittedSubtreesValue != null) validator.IntersectPermittedSubtree(constraints.PermittedSubtreesValue.Elements);
        if (constraints.ExcludedSubtreesValue != null) {
            foreach (var subtree in constraints.ExcludedSubtreesValue.GetElements()) validator.AddExcludedSubtree(subtree);
        }
        for (int index = 0; index < path.Count; index++) {
            var certificate = path[index];
            if (index != 0 && certificate.SubjectDN.Equivalent(certificate.IssuerDN)) continue;
            validator.CheckDN(certificate.SubjectDN);
            foreach (var email in certificate.SubjectDN.GetValueList(X509Name.EmailAddress)) validator.CheckEmail(email);
            var names = certificate.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (names == null) continue;
            foreach (var name in GeneralNames.GetInstance(names.GetOctets()).GetNames()) validator.CheckName(name);
        }
    }

    private static bool AllowsTlsServer(BcCertificate certificate) {
        var usages = certificate.GetExtendedKeyUsage();
        return usages == null || usages.Any(usage => usage.ToString() == KeyPurposeID.id_kp_serverAuth.ToString()
            || usage.ToString() == KeyPurposeID.AnyExtendedKeyUsage.ToString());
    }

    private static void SetAuthentication(DANERecordAnalysis record, DaneAuthenticationStatus status, string explanation) {
        record.AuthenticationStatus = status;
        record.AuthenticationExplanation = explanation;
    }
}
