using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        private async Task QueryCtLogs(CancellationToken cancellationToken)
        {
            PresentInCtLogs = false;
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

            var entries = await _ctLogAggregator.QueryAsync(fingerprint, cancellationToken).ConfigureAwait(false);
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
