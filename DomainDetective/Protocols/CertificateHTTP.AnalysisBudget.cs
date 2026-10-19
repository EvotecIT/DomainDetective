using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        /// <summary>
        /// Retrieves the certificate from the specified HTTPS endpoint.
        /// </summary>
        /// <param name="url">URL to query.</param>
        /// <param name="port">Port number to use.</param>
        /// <param name="logger">Logger instance for diagnostics.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeUrl(string url, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (AnalysisTimeout <= TimeSpan.Zero) { throw new ArgumentOutOfRangeException(nameof(AnalysisTimeout)); }
            if (ProtocolProbeTimeout <= TimeSpan.Zero) { throw new ArgumentOutOfRangeException(nameof(ProtocolProbeTimeout)); }
            ResetObservedState();
            using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "CERT", target: url);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(AnalysisTimeout);
            try {
                await AnalyzeUrlCore(url, port, logger, deadline.Token).ConfigureAwait(false);
                deadline.Token.ThrowIfCancellationRequested();
                cancellationToken.ThrowIfCancellationRequested();
                AnalysisComplete = !_ctLookupIncomplete;
            } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested) {
                logger.WriteInformationCode("CERT.Analysis.Incomplete", "Certificate analysis budget exhausted; remaining enrichment was not checked.");
                if (Certificate == null) {
                    FailureKind = CertificateFailureKind.Timeout;
                    FailureReason = "Certificate analysis budget exhausted.";
                }
            }
        }

    }
}
