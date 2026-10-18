using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        private bool _ctLookupIncomplete;

        private async Task QueryCtLogs(CancellationToken cancellationToken, InternalLogger? logger = null)
        {
            PresentInCtLogs = false;
            CtLookupComplete = false;
            _ctLogEntries.Clear();
            _ctDiscoverySources = Array.Empty<string>();
            _ctTemplateFormatErrors = Array.Empty<string>();
            if (Certificate == null)
            {
                return;
            }
            byte[] hashBytes;
#if NET8_0_OR_GREATER
            hashBytes = Certificate.GetCertHash(HashAlgorithmName.SHA256);
#else
            using (var sha = SHA256.Create()) {
                hashBytes = sha.ComputeHash(Certificate.RawData);
            }
#endif
            var fingerprint = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLowerInvariant();

            _ctLogAggregator.QueryOverride = CtLogQueryOverride;
            _ctLogAggregator.EnableCensysSource = EnableCensysCtSource;
            _ctLogAggregator.EnableShodanSource = EnableShodanCtSource;
            _ctLogAggregator.CensysApiId = FirstNonEmpty(CensysApiId, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_ID"));
            _ctLogAggregator.CensysApiSecret = FirstNonEmpty(CensysApiSecret, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_CENSYS_API_SECRET"));
            _ctLogAggregator.ShodanApiKey = FirstNonEmpty(ShodanApiKey, Environment.GetEnvironmentVariable("DOMAINDETECTIVE_SHODAN_API_KEY"));

            if (CtLookupTimeout <= TimeSpan.Zero && CtLookupTimeout != System.Threading.Timeout.InfiniteTimeSpan) {
                throw new ArgumentOutOfRangeException(nameof(CtLookupTimeout));
            }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (CtLookupTimeout != System.Threading.Timeout.InfiniteTimeSpan) { deadline.CancelAfter(CtLookupTimeout); }
            IReadOnlyList<JsonElement> entries;
            try {
                entries = await _ctLogAggregator.QueryAsync(fingerprint, deadline.Token).ConfigureAwait(false);
                deadline.Token.ThrowIfCancellationRequested();
            } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested) {
                _ctLookupIncomplete = true;
                logger?.WriteInformationCode("CERT.CT.Incomplete", "Certificate transparency lookup budget exhausted; absence from CT logs was not established.");
                entries = _ctLogAggregator.LastCompletedEntries;
            }
            _ctLogEntries.AddRange(entries);
            _ctDiscoverySources = _ctLogAggregator.LastQueriedSources
                .Where(source => !string.IsNullOrWhiteSpace(source))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            _ctTemplateFormatErrors = _ctLogAggregator.LastTemplateFormatErrors
                .Where(error => !string.IsNullOrWhiteSpace(error))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            PresentInCtLogs = _ctLogEntries.Count > 0;
            CtLookupComplete = !_ctLookupIncomplete && _ctLogAggregator.LastQueryComplete;
            if (!CtLookupComplete) {
                _ctLookupIncomplete = true;
                logger?.WriteInformationCode("CERT.CT.Incomplete", "Certificate transparency evidence is incomplete; absence from CT logs was not established.");
            }
        }

        private static string? FirstNonEmpty(string? explicitValue, string? fallbackValue) {
            if (!string.IsNullOrWhiteSpace(explicitValue)) {
                return explicitValue;
            }

            if (!string.IsNullOrWhiteSpace(fallbackValue)) {
                return fallbackValue;
            }

            return null;
        }

    }
}
