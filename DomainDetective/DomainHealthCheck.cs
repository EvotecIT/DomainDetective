using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
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
        public SpfAnalysis SpfAnalysis { get; private set; } = new SpfAnalysis();

        public DkimAnalysis DKIMAnalysis { get; private set; } = new DkimAnalysis();

        public MXAnalysis MXAnalysis { get; private set; } = new MXAnalysis();

        public CAAAnalysis CAAAnalysis { get; private set; } = new CAAAnalysis();

        public DANEAnalysis DaneAnalysis { get; private set; } = new DANEAnalysis();

        public List<DnsAnswer> Answers;

        public async Task VerifyDKIM(string domainName, string[] selectors) {
            foreach (var selector in selectors) {
                var dkim = await QueryDNS($"{selector}._domainkey.{domainName}", "TXT", DnsProvider.DnsOverHttps, "DKIM1");
                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
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
                };
            }

            foreach (var healthCheckType in healthCheckTypes) {
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await QueryDNS("_dmarc." + domainName, "TXT", DnsProvider.DnsOverHttps, "DMARC1");
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger);
                        break;
                    case HealthCheckType.SPF:
                        var spf = await QueryDNS(domainName, "TXT", DnsProvider.DnsOverHttps, "SPF1");
                        //var spf = await QueryDNS(domainName, "TXT", "DNS", "SPF1");
                        await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
                        break;
                    case HealthCheckType.DKIM:
                        if (dkimSelectors != null) {
                            foreach (var selector in dkimSelectors) {
                                var dkim = await QueryDNS($"{selector}._domainkey.{domainName}", "TXT", DnsProvider.DnsOverHttps, "DKIM1");
                                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
                            }
                        } else {
                            // lets guess DKIM selectors based on common ones - first lets create a list of common selectors
                            // TODO: Add more common selectors, and maybe guess based on MX/SPF records
                        }
                        break;
                    case HealthCheckType.MX:
                        var mx = await QueryDNS(domainName, "MX", DnsProvider.DnsOverHttps, "");
                        await MXAnalysis.AnalyzeMxRecords(mx, _logger);
                        break;
                    case HealthCheckType.CAA:
                        var caa = await QueryDNS(domainName, "CAA", DnsProvider.DnsOverHttps, "");
                        await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
                        break;
                    case HealthCheckType.DANE:
                        await VerifyDANE(domainName, daneServiceType);
                        break;
                }
            }
        }

        public async Task CheckDMARC(string dmarcRecord) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {dmarcRecord},
                    DataJoined = dmarcRecord
                }
            }, _logger);
        }

        public async Task CheckSPF(string spfRecord) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {spfRecord},
                    DataJoined = spfRecord
                }
            }, _logger);
        }

        public async Task CheckDKIM(string dkimRecord, string selector = "default") {
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsResult> {
                new DnsResult {
                    Data = new[] {dkimRecord},
                    DataJoined = dkimRecord
                }
            }, _logger);
        }

        public async Task CheckMX(string mxRecord) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {mxRecord},
                    DataJoined = mxRecord
                }
            }, _logger);
        }

        public async Task CheckCAA(string caaRecord) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {caaRecord},
                    DataJoined = caaRecord
                }
            }, _logger);
        }
        public async Task CheckCAA(List<string> caaRecords) {
            var dnsResults = caaRecords.Select(record => new DnsResult {
                Data = new[] { record },
                DataJoined = record
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }

        public async Task CheckDANE(string daneRecord) {
            await DaneAnalysis.AnalyzeDANERecords(new List<DnsResult> {
                new DnsResult {
                    Data = new[] {daneRecord},
                    DataJoined = daneRecord
                }
            }, _logger);
        }

        public async Task VerifyDANE(string domainName, int[] ports) {
            var allDaneRecords = new List<DnsResult>();
            foreach (var port in ports) {
                var dane = await QueryDNS($"_{port}._tcp.{domainName}", "TLSA", DnsProvider.DnsOverHttps, "");
                allDaneRecords.AddRange(dane);
            }

            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes) {
            if (serviceTypes == null || serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            var allDaneRecords = new List<DnsResult>();
            foreach (var serviceType in serviceTypes) {
                string service;
                int port;
                switch (serviceType) {
                    case ServiceType.SMTP:
                        service = "MX";
                        port = (int)ServiceType.SMTP;
                        break;
                    case ServiceType.HTTPS:
                        service = "A";
                        port = (int)ServiceType.HTTPS;
                        break;
                    default:
                        throw new System.Exception("Service type not implemented.");
                }

                var records = await QueryDNS(domainName, service, DnsProvider.DnsOverHttps, "");
                var recordData = records.SelectMany(x => x.Data).ToList();
                foreach (var record in recordData) {
                    var domain = service == "MX" ? record.Split(' ')[1] : record;
                    var dan = await QueryDNS($"_{port}._tcp.{domain}", "TLSA", DnsProvider.DnsOverHttps, "");
                    if (dan.Any()) {
                        var dane = dan.ToList();
                        for (int i = 0; i < dane.Count; i++) {
                            dane[i].ServiceType = serviceType;
                        }
                        allDaneRecords.AddRange(dane);
                    }
                }
            }
            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }
    }
}
