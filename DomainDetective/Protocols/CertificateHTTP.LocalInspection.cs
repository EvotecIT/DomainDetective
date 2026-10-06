using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        /// <summary>
        /// Analyzes a provided certificate without performing any network operations.
        /// </summary>
        /// <param name="certificate">Certificate instance to inspect.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) {
            Certificate = CertificateLoaderCompat.Clone(certificate);
            IsSelfSigned = false;
            ResetChainSourceTracking();
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            IsValid = chain.Build(certificate);
            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
            }
            RecordChainSource(SkipRevocation ? ChainSourceLocalBuildNoCheck : ChainSourceLocalBuildOnline);
            IsSelfSigned = IsSelfSignedCertificate(Certificate);
            PopulateKeyInfo();
            DaysToExpire = (int)(certificate.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(certificate.NotAfter - certificate.NotBefore).TotalDays;
            IsExpired = certificate.NotAfter < DateTime.Now;
            if (CaptureExtendedMetadata && !SkipRevocation) {
                await QueryRevocationEndpoints(cancellationToken);
            }
            PopulateSubjectAlternativeNames();
            if (CaptureExtendedMetadata || CaptureCtMetadata) {
                await QueryCtLogs(cancellationToken);
            }
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
                Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
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
