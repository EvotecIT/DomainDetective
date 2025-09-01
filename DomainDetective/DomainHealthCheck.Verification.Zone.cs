using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Attempts zone transfers against authoritative name servers.
        /// </summary>
        public async Task VerifyZoneTransfer(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var nsRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            var servers = nsRecords.Select(r => r.Data.Trim('.'));
            await ZoneTransferAnalysis.AnalyzeServers(domainName, servers, _logger, cancellationToken);
        }

        /// <summary>
        /// Validates delegation information against the parent zone.
        /// </summary>
        public async Task VerifyDelegation(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            NSAnalysis.Subject = domainName;
            await NSAnalysis.AnalyzeNsRecords(ns, _logger);
            await NSAnalysis.AnalyzeParentDelegation(domainName, _logger);
        }
    }
}
