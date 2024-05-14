using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using DnsClientX;

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

        public DANEAnalysis DaneAnalysis { get; private set; } = new DANEAnalysis();

        public DNSBLAnalysis DNSBLAnalysis { get; private set; }

        public CertificateAnalysis CertificateAnalysis { get; private set; } = new CertificateAnalysis();

        public SecurityTXTAnalysis SecurityTXTAnalysis { get; private set; } = new SecurityTXTAnalysis();

        public WhoisAnalysis WhoisAnalysis { get; private set; } = new WhoisAnalysis();

        public List<DnsAnswer> Answers;

        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        public DomainHealthCheck(DnsEndpoint dnsEndpoint = DnsEndpoint.System, InternalLogger internalLogger = null) {
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

            DNSBLAnalysis = new DNSBLAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            _logger.WriteVerbose("DomainHealthCheck initialized.");
            _logger.WriteVerbose("DnsEndpoint: {0}", DnsEndpoint);
            _logger.WriteVerbose("DnsSelectionStrategy: {0}", DnsSelectionStrategy);
        }

        public async Task VerifyDKIM(string domainName, string[] selectors) {
            foreach (var selector in selectors) {
                var dkim = await DnsConfiguration.QueryDNS(name: $"{selector}._domainkey.{domainName}", recordType: DnsRecordType.TXT, filter: "DKIM1");
                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, logger: _logger);
            }
        }

        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null, ServiceType[] daneServiceType = null) {
            if (healthCheckTypes == null || healthCheckTypes.Length == 0) {
                healthCheckTypes = new[]                {
                    HealthCheckType.DMARC,
                    HealthCheckType.SPF,
                    HealthCheckType.DKIM,
                    HealthCheckType.MX,
                    HealthCheckType.CAA,
                    HealthCheckType.DANE,
                    HealthCheckType.DNSBL
                };
            }

            foreach (var healthCheckType in healthCheckTypes) {
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await DnsConfiguration.QueryDNS("_dmarc." + domainName, DnsRecordType.TXT, "DMARC1");
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger);
                        break;
                    case HealthCheckType.SPF:
                        var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1");
                        await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
                        break;
                    case HealthCheckType.DKIM:
                        if (dkimSelectors != null) {
                            foreach (var selector in dkimSelectors) {
                                var dkim = await DnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1");
                                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
                            }
                        } else {
                            // lets guess DKIM selectors based on common ones - first lets create a list of common selectors
                            // TODO: Add more common selectors, and maybe guess based on MX/SPF records
                        }
                        break;
                    case HealthCheckType.MX:
                        var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX);
                        await MXAnalysis.AnalyzeMxRecords(mx, _logger);
                        break;
                    case HealthCheckType.CAA:
                        var caa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.CAA);
                        await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
                        break;
                    case HealthCheckType.DANE:
                        await VerifyDANE(domainName, daneServiceType);
                        break;
                    case HealthCheckType.DNSBL:
                        await DNSBLAnalysis.AnalyzeDNSBLRecordsMX(domainName, _logger);
                        break;
                    case HealthCheckType.SECURITYTXT:
                        // lets reset the SecurityTXTAnalysis, so it's overwritten completly on next run
                        SecurityTXTAnalysis = new SecurityTXTAnalysis();
                        await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger);
                        break;
                }
            }
        }

        public async Task CheckDMARC(string dmarcRecord) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dmarcRecord,
                }
            }, _logger);
        }

        public async Task CheckSPF(string spfRecord) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = spfRecord
                }
            }, _logger);
        }

        public async Task CheckDKIM(string dkimRecord, string selector = "default") {
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dkimRecord
                }
            }, _logger);
        }

        public async Task CheckMX(string mxRecord) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = mxRecord
                }
            }, _logger);
        }

        public async Task CheckCAA(string caaRecord) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = caaRecord
                }
            }, _logger);
        }
        public async Task CheckCAA(List<string> caaRecords) {
            var dnsResults = caaRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }

        public async Task CheckDANE(string daneRecord) {
            await DaneAnalysis.AnalyzeDANERecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = daneRecord
                }
            }, _logger);
        }


        public async Task VerifySPF(string domainName) {
            var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1");
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
        }

        public async Task VerifyDANE(string domainName, int[] ports) {
            var allDaneRecords = new List<DnsAnswer>();
            foreach (var port in ports) {
                var dane = await DnsConfiguration.QueryDNS($"_{port}._tcp.{domainName}", DnsRecordType.TLSA);
                allDaneRecords.AddRange(dane);
            }

            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes) {
            if (serviceTypes == null || serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            var allDaneRecords = new List<DnsAnswer>();
            foreach (var serviceType in serviceTypes) {
                DnsRecordType service;
                int port;
                switch (serviceType) {
                    case ServiceType.SMTP:
                        service = DnsRecordType.MX;
                        port = (int)ServiceType.SMTP;
                        break;
                    case ServiceType.HTTPS:
                        service = DnsRecordType.A;
                        port = (int)ServiceType.HTTPS;
                        break;
                    default:
                        throw new System.Exception("Service type not implemented.");
                }

                var records = await DnsConfiguration.QueryDNS(domainName, service);
                //var recordData = records.SelectMany(x => x.Data).ToList();
                //foreach (var record in recordData) {
                //    var domain = service == DnsRecordType.MX ? record.Split(' ')[1] : record;
                //    var dan = await DnsConfiguration.QueryDNS($"_{port}._tcp.{domain}", DnsRecordType.TLSA);
                //    if (dan.Any()) {
                //        var dane = dan.ToList();
                //        //for (int i = 0; i < dane.Count; i++) {
                //        //    dane[i].ServiceType = serviceType;
                //        //}
                //        allDaneRecords.AddRange(dane);
                //    }
                //}
                var recordData = records.Select(x => x.Data);
                foreach (var record in recordData) {
                    var domain = service == DnsRecordType.MX ? record.Split(' ')[1].Trim('.') : record;
                    var daneRecord = $"_{port}._tcp.{domain}";
                    var dane = await DnsConfiguration.QueryDNS(daneRecord, DnsRecordType.TLSA);
                    if (dane.Any()) {
                        allDaneRecords.AddRange(dane);
                    }
                }

            }
            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyWebsiteCertificate(string url, int port = 443) {
            await CertificateAnalysis.AnalyzeUrl(url, port, _logger);
        }

        public async Task CheckDNSBL(string ipAddress) {
            await DNSBLAnalysis.AnalyzeDNSBLRecords(ipAddress, _logger);
        }

        public async Task CheckDNSBL(string[] ipAddresses) {
            var tasks = ipAddresses.Select(ip => DNSBLAnalysis.AnalyzeDNSBLRecords(ip, _logger));
            await Task.WhenAll(tasks);
        }

        public async Task CheckWHOIS(string domain) {
            var tasks = WhoisAnalysis.QueryWhoisServer(domain);
            await Task.WhenAll(tasks);
        }
    }
}
