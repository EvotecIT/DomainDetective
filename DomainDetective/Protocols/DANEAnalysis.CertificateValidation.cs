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
    public void ValidateCertificateAssociations(IEnumerable<DaneCertificateEvidence> evidence, InternalLogger logger) {
        if (evidence == null) {
            throw new ArgumentNullException(nameof(evidence));
        }

        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DANE", target: Subject);
        var byOwner = evidence
            .Where(item => !string.IsNullOrWhiteSpace(item.TlsaOwnerName))
            .GroupBy(item => item.TlsaOwnerName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var record in AnalysisResults.Where(item => item.ValidDANERecord)) {
            using var _scope = _collector.PushTarget(record.DomainName);
            if (!byOwner.TryGetValue(record.DomainName, out var serviceEvidence)) {
                continue;
            }
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
                var matched = candidates.Any(certificate => MatchesAssociation(record, certificate));
                record.AssociationMatchStatus = matched ? DaneAssociationMatchStatus.Match : DaneAssociationMatchStatus.NoMatch;
                if (matched) {
                    logger.WriteInformationCode(DaneCodes.CertificateMatches, "TLSA association data matched live certificate evidence for {0}.", record.DomainName);
                } else {
                    logger.WriteErrorCode(DaneCodes.CertificateMismatch, "TLSA association data did not match live certificate evidence for {0}.", record.DomainName);
                }
            } catch (Exception ex) when (ex is CryptographicException || ex is FormatException || ex is ArgumentException) {
                record.AssociationMatchStatus = DaneAssociationMatchStatus.CheckFailed;
                logger.WriteWarningCode(DaneCodes.CertificateCheckFailed, "TLSA certificate comparison failed for {0}: {1}", record.DomainName, ex.Message);
            }
        }
    }

    private static IEnumerable<X509Certificate2> SelectCandidates(TlsaUsage usage, DaneCertificateEvidence evidence) {
        if (usage == TlsaUsage.PkixEe || usage == TlsaUsage.DaneEe) {
            yield return evidence.EndEntityCertificate!;
            yield break;
        }

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
    /// <summary>Certificates supplied or built for the service chain.</summary>
    public IReadOnlyList<X509Certificate2> CertificateChain { get; set; } = Array.Empty<X509Certificate2>();
    /// <summary>True when normal PKIX path validation succeeded.</summary>
    public bool PkixValidated { get; set; }
    /// <summary>True when the TLSA DNS response was validated through DNSSEC.</summary>
    public bool DnssecValidated { get; set; }
}
