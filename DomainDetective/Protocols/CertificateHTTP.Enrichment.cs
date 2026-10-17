using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        private async Task FinalizeCapturedCertificateAsync(string url, int port, InternalLogger logger, CancellationToken cancellationToken)
        {
            async Task MeasureAsync(string phase, Func<Task> action) {
                var elapsed = System.Diagnostics.Stopwatch.StartNew();
                logger?.WriteVerbose("Certificate {0} started.", phase);
                try { await action().ConfigureAwait(false); }
                finally { logger?.WriteVerbose("Certificate {0} completed in {1} ms.", phase, elapsed.ElapsedMilliseconds); }
            }
            EnsureChainBuilt(Certificate!);
            PopulateKeyInfo();
            DaysToExpire = (int)(Certificate!.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(Certificate!.NotAfter - Certificate!.NotBefore).TotalDays;
            IsExpired = Certificate!.NotAfter < DateTime.Now;
            PopulateSubjectAlternativeNames();
            var phases = new List<Task>();
            if (CaptureTlsDetails) {
                phases.Add(MeasureAsync("TLS details", () => PopulateTlsInfo(new Uri(url), port, cancellationToken)));
            }
            if (CaptureExtendedMetadata && !SkipRevocation) {
                phases.Add(MeasureAsync("revocation", () => QueryRevocationEndpoints(cancellationToken)));
            }
            if (CaptureExtendedMetadata) {
                PopulateSctAndTlsFeature(logger);
                phases.Add(MeasureAsync("protocol versions", () => ProbeProtocolSupport(new Uri(url), port, logger, cancellationToken)));
                phases.Add(MeasureAsync("stapling", () => ProbeOcspStaplingWithOpenSsl(new Uri(url), port, logger, cancellationToken)));
            }
            if (CaptureExtendedMetadata || CaptureCtMetadata) {
                phases.Add(MeasureAsync("CT lookup", () => QueryCtLogs(cancellationToken, logger)));
            }
            // Observe every owned phase before returning, including error/cancellation paths.
            await Task.WhenAll(phases).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (CaptureExtendedMetadata) { ComputeGrade(logger); }
        }

    }
}
