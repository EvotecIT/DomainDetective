using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
        public DnsEndpoint DnsEndpoint {
            get => DnsConfiguration.DnsEndpoint;
            set {
                _logger.WriteVerbose("Setting DnsEndpoint to {0}", value);
                DnsConfiguration.DnsEndpoint = value;
            }
        }

        public DnsSelectionStrategy DnsSelectionStrategy {
            get => DnsConfiguration.DnsSelectionStrategy;
            set {
                _logger.WriteVerbose("Setting DnsSelectionStrategy to {0}", value);
                DnsConfiguration.DnsSelectionStrategy = value;
            }
        }

        /// <summary>
        /// Gets the dmarc analysis.
        /// </summary>
        /// <value>
        /// The dmarc analysis.
        /// </value>
        public DmarcAnalysis DmarcAnalysis { get; private set; } = new DmarcAnalysis();

        /// <summary>
        /// Gets the SPF analysis.
        /// </summary>
        /// <value>
        /// The SPF analysis.
        /// </value>
        public SpfAnalysis SpfAnalysis { get; private set; }

        public DkimAnalysis DKIMAnalysis { get; private set; } = new DkimAnalysis();

        public MXAnalysis MXAnalysis { get; private set; }

        public CAAAnalysis CAAAnalysis { get; private set; } = new CAAAnalysis();

        public NSAnalysis NSAnalysis { get; private set; } = new NSAnalysis();

        public DANEAnalysis DaneAnalysis { get; private set; } = new DANEAnalysis();

        public DNSBLAnalysis DNSBLAnalysis { get; private set; }

        public DNSSecAnalysis DNSSecAnalysis { get; private set; } = new DNSSecAnalysis();

        public MTASTSAnalysis MTASTSAnalysis { get; private set; } = new MTASTSAnalysis();

        public CertificateAnalysis CertificateAnalysis { get; private set; } = new CertificateAnalysis();

        public SecurityTXTAnalysis SecurityTXTAnalysis { get; private set; } = new SecurityTXTAnalysis();

        public SOAAnalysis SOAAnalysis { get; private set; } = new SOAAnalysis();

        public WhoisAnalysis WhoisAnalysis { get; private set; } = new WhoisAnalysis();

        public OpenRelayAnalysis OpenRelayAnalysis { get; private set; } = new OpenRelayAnalysis();

        public STARTTLSAnalysis StartTlsAnalysis { get; private set; } = new STARTTLSAnalysis();

        public TLSRPTAnalysis TLSRPTAnalysis { get; private set; } = new TLSRPTAnalysis();

        public HttpAnalysis HttpAnalysis { get; private set; } = new HttpAnalysis();

        public List<DnsAnswer> Answers;

        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        public DomainHealthCheck(DnsEndpoint dnsEndpoint = DnsEndpoint.CloudflareWireFormat, InternalLogger internalLogger = null) {
            if (internalLogger != null) {
                _logger = internalLogger;
            }
            DnsEndpoint = dnsEndpoint;
            DnsSelectionStrategy = DnsSelectionStrategy.First;

            SpfAnalysis = new SpfAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            MXAnalysis = new MXAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            NSAnalysis = new NSAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            DNSBLAnalysis = new DNSBLAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            _logger.WriteVerbose("DomainHealthCheck initialized.");
            _logger.WriteVerbose("DnsEndpoint: {0}", DnsEndpoint);
            _logger.WriteVerbose("DnsSelectionStrategy: {0}", DnsSelectionStrategy);
        }

        public async Task VerifyDKIM(string domainName, string[] selectors, CancellationToken cancellationToken = default) {
            if (selectors == null || selectors.Length == 0) {
                throw new ArgumentException("No DKIM selectors provided.", nameof(selectors));
            }
            foreach (var selector in selectors) {
                var dkim = await DnsConfiguration.QueryDNS(name: $"{selector}._domainkey.{domainName}", recordType: DnsRecordType.TXT, filter: "DKIM1", cancellationToken: cancellationToken);
                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, logger: _logger);
            }
        }

        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null, ServiceType[] daneServiceType = null, CancellationToken cancellationToken = default) {
            if (healthCheckTypes == null || healthCheckTypes.Length == 0) {
                healthCheckTypes = new[]                {
                    HealthCheckType.DMARC,
                    HealthCheckType.SPF,
                    HealthCheckType.DKIM,
                    HealthCheckType.MX,
                    HealthCheckType.CAA,
                    HealthCheckType.DANE,
                    HealthCheckType.DNSSEC,
                    HealthCheckType.DNSBL
                };
            }

            foreach (var healthCheckType in healthCheckTypes) {
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await DnsConfiguration.QueryDNS("_dmarc." + domainName, DnsRecordType.TXT, "DMARC1", cancellationToken);
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger);
                        break;
                    case HealthCheckType.SPF:
                        var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1", cancellationToken);
                        await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
                        break;
                    case HealthCheckType.DKIM:
                        var selectors = dkimSelectors;
                        if (selectors == null || selectors.Length == 0) {
                            selectors = Definitions.DKIMSelectors.GuessSelectors().ToArray();
                        }

                        foreach (var selector in selectors) {
                            var dkim = await DnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1", cancellationToken);
                            await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
                        }
                        break;
                    case HealthCheckType.MX:
                        var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        await MXAnalysis.AnalyzeMxRecords(mx, _logger);
                        break;
                    case HealthCheckType.CAA:
                        var caa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.CAA, cancellationToken: cancellationToken);
                        await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
                        break;
                    case HealthCheckType.NS:
                        var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
                        await NSAnalysis.AnalyzeNsRecords(ns, _logger);
                        break;
                    case HealthCheckType.DANE:
                        await VerifyDANE(domainName, daneServiceType, cancellationToken);
                        break;
                    case HealthCheckType.DNSSEC:
                        DNSSecAnalysis = new DNSSecAnalysis();
                        await DNSSecAnalysis.Analyze(domainName, _logger, DnsConfiguration);
                        break;
                    case HealthCheckType.DNSBL:
                        await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(domainName, _logger);
                        break;
                    case HealthCheckType.MTASTS:
                        MTASTSAnalysis = new MTASTSAnalysis();
                        await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
                        break;
                    case HealthCheckType.TLSRPT:
                        TLSRPTAnalysis = new TLSRPTAnalysis();
                        var tlsrpt = await DnsConfiguration.QueryDNS("_smtp._tls." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
                        await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger);
                        break;
                    case HealthCheckType.SECURITYTXT:
                        // lets reset the SecurityTXTAnalysis, so it's overwritten completly on next run
                        SecurityTXTAnalysis = new SecurityTXTAnalysis();
                        await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger);
                        break;
                    case HealthCheckType.SOA:
                        var soa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.SOA, cancellationToken: cancellationToken);
                        await SOAAnalysis.AnalyzeSoaRecords(soa, _logger);
                        break;
                    case HealthCheckType.OPENRELAY:
                        var mxRecordsForRelay = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var hosts = mxRecordsForRelay.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        foreach (var host in hosts) {
                            await OpenRelayAnalysis.AnalyzeServer(host, 25, _logger);
                        }
                        break;
                    case HealthCheckType.STARTTLS:
                        var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        await StartTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger);
                        break;
                    case HealthCheckType.HTTP:
                        await HttpAnalysis.AnalyzeUrl($"http://{domainName}", true, _logger);
                        break;
                }
            }
        }

        public async Task CheckDMARC(string dmarcRecord, CancellationToken cancellationToken = default) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dmarcRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        public async Task CheckSPF(string spfRecord, CancellationToken cancellationToken = default) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = spfRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        public async Task CheckDKIM(string dkimRecord, string selector = "default", CancellationToken cancellationToken = default) {
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dkimRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        public async Task CheckMX(string mxRecord, CancellationToken cancellationToken = default) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = mxRecord,
                    Type = DnsRecordType.MX
                }
            }, _logger);
        }

        public async Task CheckCAA(string caaRecord, CancellationToken cancellationToken = default) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = caaRecord,
                    Type = DnsRecordType.CAA
                }
            }, _logger);
        }
        public async Task CheckCAA(List<string> caaRecords, CancellationToken cancellationToken = default) {
            var dnsResults = caaRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }

        public async Task CheckNS(string nsRecord, CancellationToken cancellationToken = default) {
            await NSAnalysis.AnalyzeNsRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = nsRecord,
                    Type = DnsRecordType.NS
                }
            }, _logger);
        }
        public async Task CheckNS(List<string> nsRecords, CancellationToken cancellationToken = default) {
            var dnsResults = nsRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();
            await NSAnalysis.AnalyzeNsRecords(dnsResults, _logger);
        }

        public async Task CheckDANE(string daneRecord, CancellationToken cancellationToken = default) {
            await DaneAnalysis.AnalyzeDANERecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = daneRecord
                }
            }, _logger);
        }

        public async Task CheckSOA(string soaRecord, CancellationToken cancellationToken = default) {
            await SOAAnalysis.AnalyzeSoaRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = soaRecord,
                    Type = DnsRecordType.SOA
                }
            }, _logger);
        }

        public async Task CheckOpenRelayHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await OpenRelayAnalysis.AnalyzeServer(host, port, _logger);
        }

        public async Task CheckStartTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await StartTlsAnalysis.AnalyzeServer(host, port, _logger);
        }

        public async Task CheckTLSRPT(string tlsRptRecord, CancellationToken cancellationToken = default) {
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = tlsRptRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }


        public async Task VerifySPF(string domainName, CancellationToken cancellationToken = default) {
            var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1", cancellationToken);
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
        }

        public async Task VerifyMTASTS(string domainName, CancellationToken cancellationToken = default) {
            MTASTSAnalysis = new MTASTSAnalysis();
            await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
        }

        public async Task VerifySTARTTLS(string domainName, CancellationToken cancellationToken = default) {
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await StartTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger);
        }

        public async Task VerifyTLSRPT(string domainName, CancellationToken cancellationToken = default) {
            TLSRPTAnalysis = new TLSRPTAnalysis();
            var tlsrpt = await DnsConfiguration.QueryDNS("_smtp._tls." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger);
        }

        public async Task VerifyDANE(string domainName, int[] ports, CancellationToken cancellationToken = default) {
            var allDaneRecords = new List<DnsAnswer>();
            foreach (var port in ports) {
                var dane = await DnsConfiguration.QueryDNS($"_{port}._tcp.{domainName}", DnsRecordType.TLSA, cancellationToken: cancellationToken);
                allDaneRecords.AddRange(dane);
            }

            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes, CancellationToken cancellationToken = default) {
            if (serviceTypes == null || serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            serviceTypes = serviceTypes.Distinct().ToArray();

            var allDaneRecords = new List<DnsAnswer>();
            foreach (var serviceType in serviceTypes) {
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
                        var aRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.A, cancellationToken: cancellationToken);
                        var aaaaRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.AAAA, cancellationToken: cancellationToken);
                        records = (aRecords ?? Array.Empty<DnsAnswer>()).Concat(aaaaRecords ?? Array.Empty<DnsAnswer>());
                        break;
                    default:
                        throw new System.Exception("Service type not implemented.");
                }

                var recordData = records.Select(x => x.Data).Distinct();
                foreach (var record in recordData) {
                    var domain = fromMx ? record.Split(' ')[1].Trim('.') : record;
                    var daneRecord = $"_{port}._tcp.{domain}";
                    var dane = await DnsConfiguration.QueryDNS(daneRecord, DnsRecordType.TLSA, cancellationToken: cancellationToken);
                    if (dane.Any()) {
                        allDaneRecords.AddRange(dane);
                    }
                }

            }
            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyWebsiteCertificate(string url, int port = 443, CancellationToken cancellationToken = default) {
            await CertificateAnalysis.AnalyzeUrl(url, port, _logger, cancellationToken);
        }

        public async Task CheckDNSBL(string ipAddress, CancellationToken cancellationToken = default) {
            await DNSBLAnalysis.AnalyzeDNSBLRecords(ipAddress, _logger);
        }

        public async Task CheckDNSBL(string[] ipAddresses, CancellationToken cancellationToken = default) {
            var tasks = ipAddresses.Select(ip => DNSBLAnalysis.AnalyzeDNSBLRecords(ip, _logger));
            await Task.WhenAll(tasks);
        }

        public async Task CheckWHOIS(string domain, CancellationToken cancellationToken = default) {
            WhoisAnalysis = new WhoisAnalysis();
            var tasks = WhoisAnalysis.QueryWhoisServer(domain);
            await Task.WhenAll(tasks);
        }
    }
}