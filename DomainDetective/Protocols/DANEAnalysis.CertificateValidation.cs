using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

namespace DomainDetective;

public partial class DANEAnalysis {
    /// <summary>
    /// Compares parsed TLSA records with certificate evidence captured from the corresponding service.
    /// </summary>
    /// <param name="evidence">Certificate and DNSSEC evidence keyed by TLSA owner name.</param>
    /// <param name="logger">Logger used to record match, mismatch, and incomplete-validation outcomes.</param>
    /// <remarks>DANE-TA path checks are offline; no CRL or OCSP retrieval is performed.</remarks>
    public void ValidateCertificateAssociations(IEnumerable<DaneCertificateEvidence> evidence, InternalLogger logger) {
        if (evidence == null) {
            throw new ArgumentNullException(nameof(evidence));
        }

        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DANE", target: Subject);
        var byOwner = evidence
            .Where(item => !string.IsNullOrWhiteSpace(item.TlsaOwnerName))
            .GroupBy(item => item.TlsaOwnerName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        var validationCodes = new[] { DaneCodes.CertificateMatches, DaneCodes.CertificateMismatch, DaneCodes.CertificateCheckFailed,
            DaneCodes.DnssecNotValidated, DaneCodes.PkixNotValidated, DaneCodes.AuthenticationFailed, DaneCodes.Authenticated };
        Assessments.RemoveAll(assessment => assessment.Target != null && byOwner.ContainsKey(assessment.Target)
            && validationCodes.Contains(assessment.Code));

        foreach (var record in AnalysisResults.Where(item => item.ValidDANERecord)) {
            using var _scope = _collector.PushTarget(record.DomainName);
            if (!byOwner.TryGetValue(record.DomainName, out var serviceEvidence)) {
                continue;
            }
            record.AuthenticationStatus = DaneAuthenticationStatus.Inconclusive;
            record.AuthenticationExplanation = "Required authentication evidence is unavailable.";
            if (!serviceEvidence.DnssecValidated) {
                record.AssociationMatchStatus = DaneAssociationMatchStatus.CheckFailed;
                logger.WriteWarningCode(DaneCodes.DnssecNotValidated, "TLSA association for {0} was not compared because DNSSEC validation was not established.", record.DomainName);
                continue;
            }
            if (serviceEvidence.EndEntityCertificate == null) {
                record.AssociationMatchStatus = DaneAssociationMatchStatus.CheckFailed;
                logger.WriteWarningCode(DaneCodes.CertificateCheckFailed, "No service certificate was available for TLSA owner {0}.", record.DomainName);
                continue;
            }
            if ((record.CertificateUsage == TlsaUsage.PkixTa || record.CertificateUsage == TlsaUsage.PkixEe) && !serviceEvidence.PkixValidated) {
                record.AssociationMatchStatus = DaneAssociationMatchStatus.CheckFailed;
                logger.WriteWarningCode(DaneCodes.PkixNotValidated, "TLSA usage {0} requires a valid PKIX path for {1}.", record.CertificateUsage, record.DomainName);
                continue;
            }

            try {
                var candidates = SelectCandidates(record.CertificateUsage, serviceEvidence).ToArray();
                var matching = candidates.Where(certificate => MatchesAssociation(record, certificate)).ToArray();
                AuthenticateCertificate(record, serviceEvidence, matching);
                var matched = matching.Length > 0;
                record.AssociationMatchStatus = matched ? DaneAssociationMatchStatus.Match : DaneAssociationMatchStatus.NoMatch;
                if (matched) {
                    logger.WriteInformationCode(DaneCodes.CertificateMatches, "TLSA association data matched live certificate evidence for {0}.", record.DomainName);
                }
            } catch (Exception ex) when (ex is CryptographicException || ex is FormatException || ex is ArgumentException
                || ex is Org.BouncyCastle.Security.Certificates.CertificateException) {
                record.AssociationMatchStatus = DaneAssociationMatchStatus.CheckFailed;
                record.AuthenticationStatus = DaneAuthenticationStatus.Failed;
                record.AuthenticationExplanation = "Certificate evidence could not be decoded: " + ex.Message;
                logger.WriteWarningCode(DaneCodes.CertificateCheckFailed, "TLSA certificate comparison failed for {0}: {1}", record.DomainName, ex.Message);
            }
        }
        foreach (var service in AnalysisResults.Where(record => record.ValidDANERecord && byOwner.ContainsKey(record.DomainName))
            .GroupBy(record => record.DomainName, StringComparer.OrdinalIgnoreCase)) {
            using var scope = _collector.PushTarget(service.Key);
            if (service.Any(record => record.AuthenticationStatus == DaneAuthenticationStatus.Authenticated)) {
                logger.WriteInformationCode(DaneCodes.Authenticated, "TLSA authentication succeeded for {0} using at least one usable alternative.", service.Key);
            } else {
                if (service.Any(record => record.AssociationMatchStatus == DaneAssociationMatchStatus.NoMatch)) {
                    if (service.All(record => record.AuthenticationStatus == DaneAuthenticationStatus.Failed))
                        logger.WriteErrorCode(DaneCodes.CertificateMismatch, "No usable TLSA alternative matched and authenticated the certificate evidence for {0}.", service.Key);
                    else logger.WriteWarningCode(DaneCodes.CertificateMismatch, "Unmatched TLSA alternatives for {0}; authentication evidence remains incomplete.", service.Key);
                }
                if (service.All(record => record.AuthenticationStatus == DaneAuthenticationStatus.Failed))
                    logger.WriteErrorCode(DaneCodes.AuthenticationFailed, "Every usable TLSA alternative failed service authentication for {0}.", service.Key);
            }
        }
    }

    private static IEnumerable<X509Certificate2> SelectCandidates(TlsaUsage usage, DaneCertificateEvidence evidence) {
        if (usage == TlsaUsage.PkixEe || usage == TlsaUsage.DaneEe) {
            yield return evidence.EndEntityCertificate!;
            yield break;
        }

        // A DANE-TA association can designate the end entity itself as the trust anchor.
        if (usage == TlsaUsage.DaneTa) yield return evidence.EndEntityCertificate!;

        foreach (var certificate in evidence.CertificateChain) {
            if (!certificate.RawData.SequenceEqual(evidence.EndEntityCertificate!.RawData)) {
                yield return certificate;
            }
        }
    }

    private static bool MatchesAssociation(DANERecordAnalysis record, X509Certificate2 certificate) {
        var selected = record.SelectorField switch {
            TlsaSelector.Cert => certificate.RawData,
            TlsaSelector.Spki => new X509CertificateParser().ReadCertificate(certificate.RawData)
                .CertificateStructure.SubjectPublicKeyInfo.GetEncoded(),
            _ => Array.Empty<byte>()
        };

        var compared = record.MatchingTypeField switch {
            TlsaMatchingType.Full => selected,
            TlsaMatchingType.Sha256 => ComputeHash(selected, SHA256.Create),
            TlsaMatchingType.Sha512 => ComputeHash(selected, SHA512.Create),
            _ => Array.Empty<byte>()
        };
        var expected = HexToBytes(record.CertificateAssociationData);
        return compared.Length > 0 && FixedTimeEquals(compared, expected);
    }

    private static byte[] ComputeHash(byte[] value, Func<HashAlgorithm> factory) {
        using var algorithm = factory();
        return algorithm.ComputeHash(value);
    }

    private static byte[] HexToBytes(string value) {
        if (value.Length % 2 != 0) {
            throw new FormatException("TLSA association data must contain whole octets.");
        }
        var result = new byte[value.Length / 2];
        for (var index = 0; index < result.Length; index++) {
            result[index] = Convert.ToByte(value.Substring(index * 2, 2), 16);
        }
        return result;
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right) {
        if (left.Length != right.Length) {
            return false;
        }
        var difference = 0;
        for (var index = 0; index < left.Length; index++) {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }
}

/// <summary>Certificate and DNSSEC evidence used to validate one TLSA owner name.</summary>
public sealed class DaneCertificateEvidence {
    /// <summary>TLSA owner name, such as <c>_443._tcp.example.com</c>.</summary>
    public string TlsaOwnerName { get; set; } = string.Empty;
    /// <summary>End-entity certificate presented by the service.</summary>
    public X509Certificate2? EndEntityCertificate { get; set; }
    /// <summary>Certificates supplied or built for the service chain. For PKIX usages, supply the path validated by <see cref="PkixValidated"/>.</summary>
    public IReadOnlyList<X509Certificate2> CertificateChain { get; set; } = Array.Empty<X509Certificate2>();
    /// <summary>True when normal PKIX path validation succeeded.</summary>
    public bool PkixValidated { get; set; }
    /// <summary>Result of the TLS engine's certificate name check against this service's TLSA base domain; null when not evaluated.</summary>
    public bool? HostnameMatch { get; set; }
    /// <summary>True when the TLSA DNS response was validated through DNSSEC.</summary>
    public bool DnssecValidated { get; set; }
}
