using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries MX records for a domain and performs analysis.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyMX(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.MX, () => VerifyMXDirectCore(domainName, cancellationToken), cancellationToken, ownerDomain: domainName);

        private async Task VerifyMXDirectCore(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            var mx = await GetMxRecordsAsync(domainName, cancellationToken);
            MXAnalysis.Subject = domainName;
            await MXAnalysis.AnalyzeMxRecords(mx, _logger, cancellationToken);
        }

        /// <summary>
        /// Analyzes a raw MX record.
        /// </summary>
        /// <param name="mxRecord">MX record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task CheckMX(string mxRecord, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.MX, () => CheckMXDirectCore(mxRecord, cancellationToken), cancellationToken);

        private async Task CheckMXDirectCore(string mxRecord, CancellationToken cancellationToken = default) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = mxRecord,
                    Type = DnsRecordType.MX
                }
            }, _logger, cancellationToken);
        }
    }
}
