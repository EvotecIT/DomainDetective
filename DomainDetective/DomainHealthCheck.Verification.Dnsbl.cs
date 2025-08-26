using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Net;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Checks domain MX hosts against configured DNS block lists.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDNSBL(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(domainName, _logger);
        }

        /// <summary>
        /// Checks a single input (IP address or domain) against configured DNS block lists.
        /// </summary>
        /// <param name="nameOrIpAddress">IP address or domain to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDNSBL(string nameOrIpAddress, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(nameOrIpAddress)) {
                throw new ArgumentNullException(nameof(nameOrIpAddress));
            }

            if (IPAddress.TryParse(nameOrIpAddress, out _)) {
                await DNSBLAnalysis.AnalyzeDNSBLRecordsMany(new[] { nameOrIpAddress }, _logger, clearExisting: true);
            } else {
                // For domain: include domain blacklists and resolve MX to check IP-based lists
                await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(nameOrIpAddress, _logger, clearExisting: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// Checks multiple inputs (IP addresses and/or domains) against DNS block lists.
        /// </summary>
        /// <param name="nameOrIpAddresses">Inputs to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDNSBL(string[] nameOrIpAddresses, CancellationToken cancellationToken = default) {
            if (nameOrIpAddresses == null) {
                throw new ArgumentNullException(nameof(nameOrIpAddresses));
            }

            var ips = new List<string>();
            var domains = new List<string>();
            foreach (var item in nameOrIpAddresses) {
                cancellationToken.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(item)) continue;
                if (IPAddress.TryParse(item, out _)) ips.Add(item);
                else domains.Add(item);
            }

            if (ips.Count > 0) {
                await DNSBLAnalysis.AnalyzeDNSBLRecordsMany(ips, _logger, clearExisting: true);
            } else {
                // ensure previous results are cleared
                DNSBLAnalysis.Reset();
                DNSBLAnalysis.Logger = _logger;
            }

            if (domains.Count > 0) {
                // append domain+MX-IP results without clearing IP results
                bool first = ips.Count == 0;
                foreach (var d in domains) {
                    await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(d, _logger, clearExisting: first);
                    first = false;
                }
            }
        }
    }
}
