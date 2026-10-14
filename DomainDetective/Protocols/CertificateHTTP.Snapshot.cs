using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using DomainDetective.Helpers;

namespace DomainDetective;

public partial class CertificateAnalysis {
    /// <summary>Copies observed evidence and options without sharing certificate ownership or mutable result containers.</summary>
    internal CertificateAnalysis CloneForSnapshot() {
        if (_disposed) throw new ObjectDisposedException(nameof(CertificateAnalysis));
        var clone = (CertificateAnalysis)MemberwiseClone();
        clone._ownedCertificates = new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();
        clone.Chain = new();
        // Every cloned certificate is newly created and belongs to the returned analysis,
        // including clones of certificates borrowed by the original through public setters.
        try {
            clone.Certificate = Certificate == null ? null : clone.OwnCertificate(CertificateLoaderCompat.Clone(Certificate));
            foreach (var certificate in Chain) clone.Chain.Add(clone.OwnCertificate(CertificateLoaderCompat.Clone(certificate)));
        } catch {
            foreach (var certificate in clone._ownedCertificates) certificate.Dispose();
            throw;
        }
        clone.ChainSourceHistory = new(ChainSourceHistory);
        clone.OcspUrls = new(OcspUrls);
        clone.CrlUrls = new(CrlUrls);
        clone.RedirectTargets = new(RedirectTargets);
        clone.SubjectAlternativeNames = new(SubjectAlternativeNames);
        clone.WildcardSubdomains = WildcardSubdomains.ToDictionary(pair => pair.Key, pair => new List<string>(pair.Value), WildcardSubdomains.Comparer);
        clone.ExtendedKeyUsageOids = new(ExtendedKeyUsageOids);
        clone.ExtendedKeyUsageFriendlyNames = new(ExtendedKeyUsageFriendlyNames);
        clone.Assessments = new(Assessments);
        clone._ctLogEntries = _ctLogEntries.Select(entry => entry.Clone()).ToList();
        clone._ctDiscoverySources = _ctDiscoverySources.ToArray();
        clone._ctTemplateFormatErrors = _ctTemplateFormatErrors.ToArray();
        clone._ctLogAggregator = new CtLogAggregator {
            EnableCensysSource = _ctLogAggregator.EnableCensysSource,
            CensysApiId = _ctLogAggregator.CensysApiId, CensysApiSecret = _ctLogAggregator.CensysApiSecret,
            CensysApiUrlTemplate = _ctLogAggregator.CensysApiUrlTemplate,
            EnableShodanSource = _ctLogAggregator.EnableShodanSource, ShodanApiKey = _ctLogAggregator.ShodanApiKey,
            ShodanApiUrlTemplate = _ctLogAggregator.ShodanApiUrlTemplate
        };
        clone._ctLogAggregator.ApiTemplates.Clear();
        clone._ctLogAggregator.ApiTemplates.AddRange(_ctLogAggregator.ApiTemplates);
        return clone;
    }
}
