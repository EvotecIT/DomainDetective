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
        /// Checks domain against DNSBL lists using a specified domain IP scan mode.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="scanMode">Controls which IPs to resolve and check for IP-based DNSBLs.</param>
        /// <param name="clearExisting">Whether to clear previous results prior to running.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDNSBL(string domainName, DomainIpScanMode scanMode, bool clearExisting = true, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(domainName, _logger, clearExisting: clearExisting, scanMode: scanMode);
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
                // Validate domain and normalize; throws ArgumentException for invalid names
                var normalized = NormalizeDomain(nameOrIpAddress);
                // Reject hostnames without a dot (heuristic for this API)
                if (normalized.IndexOf('.') < 0) {
                    throw new ArgumentException("Host name must contain a dot.", nameof(nameOrIpAddress));
                }
                // Reject IPv4-looking dotted numerics that are not valid IP addresses
                if (System.Text.RegularExpressions.Regex.IsMatch(normalized, @"^\d+(?:\.\d+){3}$")) {
                    throw new ArgumentException("Invalid IPv4 address.", nameof(nameOrIpAddress));
                }
                // For domain: include domain blacklists and resolve MX to check IP-based lists
                await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(normalized, _logger, clearExisting: true);
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
                if (IPAddress.TryParse(item, out _)) {
                    ips.Add(item);
                } else {
                    // Validate domain early to surface ArgumentException for bad inputs
                    var normalized = NormalizeDomain(item);
                    if (normalized.IndexOf('.') < 0) {
                        throw new ArgumentException("Host name must contain a dot.", nameof(nameOrIpAddresses));
                    }
                    if (System.Text.RegularExpressions.Regex.IsMatch(normalized, @"^\d+(?:\.\d+){3}$")) {
                        throw new ArgumentException("Invalid IPv4 address.", nameof(nameOrIpAddresses));
                    }
                    domains.Add(normalized);
                }
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
