using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Analyzes a single DANE record.
        /// </summary>
        /// <param name="daneRecord">TLSA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDANE(string daneRecord, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            await DaneAnalysis.AnalyzeDANERecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = daneRecord
                }
            }, _logger, cancellationToken);
        }

        /// <summary>
        /// Analyzes multiple DANE records.
        /// </summary>
        /// <param name="daneRecords">Collection of TLSA record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDANE(IEnumerable<string> daneRecords, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            var answers = daneRecords.Select(record => new DnsAnswer {
                DataRaw = record
            }).ToList();
            await DaneAnalysis.AnalyzeDANERecords(answers, _logger, cancellationToken);
        }

        /// <summary>
        /// Queries TLSA records for specific ports on a domain. Generated names use
        /// the `_tcp` or `_udp` label depending on the protocol.
        /// </summary>
        /// <param name="domainName">Domain to query.</param>
        /// <param name="ports">Ports to check for DANE.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDANE(string domainName, int[] ports, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (ports == null || ports.Length == 0) {
                throw new ArgumentException("No ports provided.", nameof(ports));
            }

            if (ports.Any(p => p <= 0)) {
                throw new ArgumentException("Ports must be greater than zero.", nameof(ports));
            }

            DaneAnalysis = new DANEAnalysis();
            DaneAnalysis.QueryDnsOverride = DaneDnsOverride;
            var allDaneRecords = new List<DnsAnswer>();
            foreach (var port in ports) {
                cancellationToken.ThrowIfCancellationRequested();
                var query = CreateServiceQuery(port, domainName);
                ValidateServiceQueryProtocol(query);
                if (!DaneAnalysis.QueriedNames.Contains(query, StringComparer.OrdinalIgnoreCase))
                    DaneAnalysis.QueriedNames.Add(query);
                if (!DaneAnalysis.QueriedPorts.Contains(port))
                    DaneAnalysis.QueriedPorts.Add(port);
                var dane = await QueryDaneDns(query, cancellationToken);
                allDaneRecords.AddRange(dane);
            }

            if (allDaneRecords.Count > 0) {
                cancellationToken.ThrowIfCancellationRequested();
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger, cancellationToken);
            } else {
                _logger.WriteWarning("No DANE records found.");
            }
        }

        /// <summary>
        /// Queries TLSA records for the provided service definitions. Generated names
        /// include the `_tcp` or `_udp` label as appropriate.
        /// </summary>
        /// <param name="services">Services to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDANE(ServiceDefinition[] services, CancellationToken cancellationToken = default) {
            if (services == null || services.Length == 0) {
                throw new ArgumentException("No services provided.", nameof(services));
            }

            DaneAnalysis = new DANEAnalysis();
            DaneAnalysis.QueryDnsOverride = DaneDnsOverride;
            var allDaneRecords = new List<DnsAnswer>();

            foreach (var service in services.Distinct()) {
                cancellationToken.ThrowIfCancellationRequested();
                var host = NormalizeDomain(service.Host).TrimEnd('.');
                var daneName = CreateServiceQuery(service.Port, host);
                ValidateServiceQueryProtocol(daneName);
                if (!DaneAnalysis.QueriedNames.Contains(daneName, StringComparer.OrdinalIgnoreCase))
                    DaneAnalysis.QueriedNames.Add(daneName);
                if (!DaneAnalysis.QueriedPorts.Contains(service.Port))
                    DaneAnalysis.QueriedPorts.Add(service.Port);
                if (service.Port == (int)ServiceType.SMTP) {
                    if (!DaneAnalysis.QueriedServiceTypes.Contains(ServiceType.SMTP))
                        DaneAnalysis.QueriedServiceTypes.Add(ServiceType.SMTP);
                } else if (service.Port == (int)ServiceType.HTTPS) {
                    if (!DaneAnalysis.QueriedServiceTypes.Contains(ServiceType.HTTPS))
                        DaneAnalysis.QueriedServiceTypes.Add(ServiceType.HTTPS);
                }
                var dane = await QueryDaneDns(daneName, cancellationToken);
                if (dane.Any()) {
                    allDaneRecords.AddRange(dane);
                }
            }

            if (allDaneRecords.Count > 0) {
                cancellationToken.ThrowIfCancellationRequested();
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger, cancellationToken);
            } else {
                _logger.WriteWarning("No DANE records found.");
            }
        }

        /// <summary>
        /// Queries TLSA records based on common service types. Generated names use
        /// the `_tcp` or `_udp` label.
        /// </summary>
        /// <param name="domainName">Domain to query.</param>
        /// <param name="serviceTypes">Services to investigate.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            DaneAnalysis = new DANEAnalysis();
            DaneAnalysis.QueryDnsOverride = DaneDnsOverride;
            if (serviceTypes == null || serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            serviceTypes = serviceTypes.Distinct().ToArray();
            if (serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            var allDaneRecords = new List<DnsAnswer>();
            foreach (var serviceType in serviceTypes) {
                cancellationToken.ThrowIfCancellationRequested();
                int port;
                IEnumerable<DnsAnswer> records;
                bool fromMx;
                switch (serviceType) {
                    case ServiceType.SMTP:
                        port = (int)ServiceType.SMTP;
                        fromMx = true;
                        records = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        break;
                    case ServiceType.HTTPS:
                        port = (int)ServiceType.HTTPS;
                        fromMx = false;
                        records = new[] { new DnsAnswer { DataRaw = domainName } };
                        break;
                    default:
                        throw new NotSupportedException("Service type not implemented.");
                }

                var recordData = records.Select(x => x.Data ?? x.DataRaw).Distinct();
                foreach (var record in recordData) {
                    cancellationToken.ThrowIfCancellationRequested();
                    string domain;
                    if (fromMx) {
                        string[] parts = record.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 2 || string.IsNullOrWhiteSpace(parts[1])) {
                            continue;
                        }
                        domain = parts[1].Trim('.');
                    } else {
                        domain = record;
                    }
                    var daneRecord = CreateServiceQuery(port, domain);
                    ValidateServiceQueryProtocol(daneRecord);
                    if (!DaneAnalysis.QueriedNames.Contains(daneRecord, StringComparer.OrdinalIgnoreCase))
                        DaneAnalysis.QueriedNames.Add(daneRecord);
                    if (!DaneAnalysis.QueriedPorts.Contains(port))
                        DaneAnalysis.QueriedPorts.Add(port);
                    if (!DaneAnalysis.QueriedServiceTypes.Contains(serviceType))
                        DaneAnalysis.QueriedServiceTypes.Add(serviceType);
                    var dane = await QueryDaneDns(daneRecord, cancellationToken);
                    if (dane.Any()) {
                        allDaneRecords.AddRange(dane);
                    }
                }

            }
            if (allDaneRecords.Count > 0) {
                cancellationToken.ThrowIfCancellationRequested();
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger, cancellationToken);
            } else {
                _logger.WriteWarning("No DANE records found.");
            }
        }
    }
}
