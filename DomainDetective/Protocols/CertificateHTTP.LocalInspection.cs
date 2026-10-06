using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        /// <summary>Inspects a supplied certificate without network access or system chain building.</summary>
        /// <param name="certificate">Certificate to inspect; ownership remains with the caller.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <remarks>Chain trust and hostname matching remain unassessed. Use <see cref="AnalyzeCertificateWithEnrichment"/> to explicitly enable chain, revocation and CT operations.</remarks>
        public Task AnalyzeCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
            AnalyzeProvidedCertificateAsync(certificate, allowNetwork: false, cancellationToken);

        /// <summary>Inspects a supplied certificate and explicitly permits network-backed chain, revocation and CT enrichment.</summary>
        /// <param name="certificate">Certificate to inspect; ownership remains with the caller.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <remarks>Existing capture and revocation options control enrichment. System chain building may download missing issuers through AIA.</remarks>
        public Task AnalyzeCertificateWithEnrichment(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
            AnalyzeProvidedCertificateAsync(certificate, allowNetwork: true, cancellationToken);

        private async Task AnalyzeProvidedCertificateAsync(X509Certificate2 certificate, bool allowNetwork, CancellationToken cancellationToken) {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (_disposed) throw new ObjectDisposedException(nameof(CertificateAnalysis));
            cancellationToken.ThrowIfCancellationRequested();
            // Clone before reset so callers may safely pass this analysis's previous leaf.
            var replacement = CertificateLoaderCompat.Clone(certificate);
            ResetObservedState();
            Certificate = OwnCertificate(replacement);
            Subject = Certificate.Subject;
            ProvidedCertificateInspection = true;
            if (allowNetwork) {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
                chain.ChainPolicy.UrlRetrievalTimeout = Timeout;
                IsValid = chain.Build(Certificate);
                ChainValidationPerformed = true;
                foreach (var element in chain.ChainElements) {
                    Chain.Add(OwnCertificate(CertificateLoaderCompat.Clone(element.Certificate)));
                }
                RecordChainSource(SkipRevocation ? ChainSourceLocalBuildNoCheck : ChainSourceLocalBuildOnline);
            } else {
                Chain.Add(OwnCertificate(CertificateLoaderCompat.Clone(Certificate)));
                RecordChainSource("local-inspection");
            }
            IsSelfSigned = IsSelfSignedCertificate(Certificate);
            PopulateKeyInfo();
            DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(Certificate.NotAfter - Certificate.NotBefore).TotalDays;
            IsExpired = Certificate.NotAfter < DateTime.Now;
            PopulateSubjectAlternativeNames();
            if (allowNetwork && CaptureExtendedMetadata && !SkipRevocation) {
                await QueryRevocationEndpoints(cancellationToken).ConfigureAwait(false);
            }
            if (allowNetwork && (CaptureExtendedMetadata || CaptureCtMetadata)) {
                await QueryCtLogs(cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
        }

        private void EnsureChainBuilt(X509Certificate2 certificate) {
            if (Chain.Count > 1) {
                return;
            }

            if (TryBuildChain(certificate, SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online)) {
                return;
            }

            if (!SkipRevocation) {
                TryBuildChain(certificate, X509RevocationMode.NoCheck);
            }
        }

        private bool TryBuildChain(X509Certificate2 certificate, X509RevocationMode revocationMode) {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = revocationMode;
            chain.ChainPolicy.UrlRetrievalTimeout = Timeout;
            chain.Build(certificate);
            if (chain.ChainElements.Count <= Chain.Count) {
                return false;
            }

            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(OwnCertificate(CertificateLoaderCompat.Clone(element.Certificate)));
            }
            RecordChainSource(revocationMode == X509RevocationMode.NoCheck ? ChainSourceLocalBuildNoCheck : ChainSourceLocalBuildOnline);
            return true;
        }

        private void ResetChainSourceTracking() {
            ChainSource = string.Empty;
            ChainSourceHistory.Clear();
        }

        private void RecordChainSource(string source) {
            if (string.IsNullOrWhiteSpace(source)) {
                return;
            }

            ChainSource = source;
            if (!ChainSourceHistory.Contains(source, StringComparer.OrdinalIgnoreCase)) {
                ChainSourceHistory.Add(source);
            }
        }

    }
}
