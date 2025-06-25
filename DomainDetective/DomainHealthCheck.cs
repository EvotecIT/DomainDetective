using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;

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

        public string MtaStsPolicyUrlOverride { get; set; }

        public CertificateAnalysis CertificateAnalysis { get; private set; } = new CertificateAnalysis();

        public SecurityTXTAnalysis SecurityTXTAnalysis { get; private set; } = new SecurityTXTAnalysis();

        public SOAAnalysis SOAAnalysis { get; private set; } = new SOAAnalysis();

        public WhoisAnalysis WhoisAnalysis { get; private set; } = new WhoisAnalysis();

        public OpenRelayAnalysis OpenRelayAnalysis { get; private set; } = new OpenRelayAnalysis();

        public STARTTLSAnalysis StartTlsAnalysis { get; private set; } = new STARTTLSAnalysis();

        public SMTPTLSAnalysis SmtpTlsAnalysis { get; private set; } = new SMTPTLSAnalysis();

        public TLSRPTAnalysis TLSRPTAnalysis { get; private set; } = new TLSRPTAnalysis();

        public BimiAnalysis BimiAnalysis { get; private set; } = new BimiAnalysis();

        public HttpAnalysis HttpAnalysis { get; private set; } = new HttpAnalysis();

        public HPKPAnalysis HPKPAnalysis { get; private set; } = new HPKPAnalysis();


        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        public DomainHealthCheck(DnsEndpoint dnsEndpoint = DnsEndpoint.CloudflareWireFormat, InternalLogger internalLogger = null) {
            if (internalLogger != null) {
                _logger = internalLogger;
            }
            DnsEndpoint = dnsEndpoint;
            DnsSelectionStrategy = DnsSelectionStrategy.First;

            DmarcAnalysis.DnsConfiguration = DnsConfiguration;

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
            DKIMAnalysis.Reset();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            if (selectors == null || selectors.Length == 0) {
                await DKIMAnalysis.QueryWellKnownSelectors(domainName, DnsConfiguration, _logger, cancellationToken);
                return;
            }

            foreach (var selector in selectors) {
                var dkim = await DnsConfiguration.QueryDNS(name: $"{selector}._domainkey.{domainName}", recordType: DnsRecordType.TXT, filter: "DKIM1", cancellationToken: cancellationToken);
                await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, logger: _logger);
            }
        }

        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null, ServiceType[] daneServiceType = null, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
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
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger, domainName);
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
                        MTASTSAnalysis = new MTASTSAnalysis {
                            PolicyUrlOverride = MtaStsPolicyUrlOverride
                        };
                        await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
                        break;
                    case HealthCheckType.TLSRPT:
                        TLSRPTAnalysis = new TLSRPTAnalysis();
                        var tlsrpt = await DnsConfiguration.QueryDNS("_smtp._tls." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
                        await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger, cancellationToken);
                        break;
                    case HealthCheckType.BIMI:
                        BimiAnalysis = new BimiAnalysis();
                        var bimi = await DnsConfiguration.QueryDNS($"default._bimi.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
                        await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken);
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
                            await OpenRelayAnalysis.AnalyzeServer(host, 25, _logger, cancellationToken);
                        }
                        break;
                    case HealthCheckType.STARTTLS:
                        var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        await StartTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.SMTPTLS:
                        var mxRecordsForSmtpTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var smtpTlsHosts = mxRecordsForSmtpTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        await SmtpTlsAnalysis.AnalyzeServers(smtpTlsHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.HTTP:
                        await HttpAnalysis.AnalyzeUrl($"http://{domainName}", true, _logger);
                        break;
                    case HealthCheckType.HPKP:
                        await HPKPAnalysis.AnalyzeUrl($"http://{domainName}", _logger);
                        break;
                    default:
                        _logger.WriteError("Unknown health check type: {0}", healthCheckType);
                        throw new NotSupportedException("Health check type not implemented.");
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
            DKIMAnalysis.Reset();
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
            await OpenRelayAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        public async Task CheckStartTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await StartTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        public async Task CheckSmtpTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await SmtpTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        public async Task CheckTLSRPT(string tlsRptRecord, CancellationToken cancellationToken = default) {
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = tlsRptRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken);
        }

        public async Task CheckBIMI(string bimiRecord, CancellationToken cancellationToken = default) {
            await BimiAnalysis.AnalyzeBimiRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = bimiRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken);
        }


        public async Task VerifySPF(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1", cancellationToken);
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
        }

        public async Task VerifyMTASTS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            MTASTSAnalysis = new MTASTSAnalysis {
                PolicyUrlOverride = MtaStsPolicyUrlOverride
            };
            await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
        }

        public async Task VerifySTARTTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await StartTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger, cancellationToken);
        }

        public async Task VerifySMTPTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await SmtpTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger, cancellationToken);
        }

        public async Task VerifyTLSRPT(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            TLSRPTAnalysis = new TLSRPTAnalysis();
            var tlsrpt = await DnsConfiguration.QueryDNS("_smtp._tls." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger, cancellationToken);
        }

        public async Task VerifyBIMI(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            BimiAnalysis = new BimiAnalysis();
            var bimi = await DnsConfiguration.QueryDNS($"default._bimi.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken);
        }

        public async Task VerifyDANE(string domainName, int[] ports, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            if (ports == null || ports.Length == 0) {
                throw new ArgumentException("No ports provided.", nameof(ports));
            }

            if (ports.Any(p => p <= 0)) {
                throw new ArgumentException("Ports must be greater than zero.", nameof(ports));
            }

            DaneAnalysis = new DANEAnalysis();
            var allDaneRecords = new List<DnsAnswer>();
            foreach (var port in ports) {
                var dane = await DnsConfiguration.QueryDNS($"_{port}._tcp.{domainName}", DnsRecordType.TLSA, cancellationToken: cancellationToken);
                allDaneRecords.AddRange(dane);
            }

            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyDANE(ServiceDefinition[] services, CancellationToken cancellationToken = default) {
            if (services == null || services.Length == 0) {
                throw new ArgumentException("No services provided.", nameof(services));
            }

            DaneAnalysis = new DANEAnalysis();
            var allDaneRecords = new List<DnsAnswer>();

            foreach (var service in services.Distinct()) {
                var host = service.Host.TrimEnd('.');
                var daneName = $"_{service.Port}._tcp.{host}";
                var dane = await DnsConfiguration.QueryDNS(daneName, DnsRecordType.TLSA, cancellationToken: cancellationToken);
                if (dane.Any()) {
                    allDaneRecords.AddRange(dane);
                }
            }

            await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
        }

        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            DaneAnalysis = new DANEAnalysis();
            if (serviceTypes == null || serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

            serviceTypes = serviceTypes.Distinct().ToArray();
            if (serviceTypes.Length == 0) {
                serviceTypes = new[] { ServiceType.SMTP, ServiceType.HTTPS };
            }

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

        /// <summary>
        /// Verifies the certificate for a website. If no scheme is provided in <paramref name="url"/>, "https://" is assumed.
        /// </summary>
        /// <param name="url">Website address. If missing a scheme, "https://" will be prepended.</param>
        /// <param name="port">Port to use for the connection.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        public async Task VerifyWebsiteCertificate(string url, int port = 443, CancellationToken cancellationToken = default) {
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                url = $"https://{url}";
            }
            await CertificateAnalysis.AnalyzeUrl(url, port, _logger, cancellationToken);
        }

        public async Task CheckDNSBL(string ipAddress, CancellationToken cancellationToken = default) {
            await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ipAddress, _logger)) {
                // enumeration triggers processing
            }
        }

        public async Task CheckDNSBL(string[] ipAddresses, CancellationToken cancellationToken = default) {
            foreach (var ip in ipAddresses) {
                await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ip, _logger)) {
                    // enumeration triggers processing
                }
            }
        }

        public async Task CheckWHOIS(string domain, CancellationToken cancellationToken = default) {
            var timeout = WhoisAnalysis.Timeout;
            WhoisAnalysis = new WhoisAnalysis { Timeout = timeout };
            await WhoisAnalysis.QueryWhoisServer(domain, cancellationToken);
        }

        public DomainSummary BuildSummary() {
            var spfValid = SpfAnalysis.SpfRecordExists && SpfAnalysis.StartsCorrectly &&
                            !SpfAnalysis.ExceedsDnsLookups && !SpfAnalysis.MultipleSpfRecords;

            return new DomainSummary {
                HasSpfRecord = SpfAnalysis.SpfRecordExists,
                SpfValid = spfValid,
                HasDmarcRecord = DmarcAnalysis.DmarcRecordExists,
                DmarcPolicy = DmarcAnalysis.Policy,
                HasDkimRecord = DKIMAnalysis.AnalysisResults.Values.Any(a => a.DkimRecordExists),
                HasMxRecord = MXAnalysis.MxRecordExists,
                DnsSecValid = DNSSecAnalysis.ChainValid
            };
        }
          
        public string ToJson(JsonSerializerOptions options = null) {
            options ??= new JsonSerializerOptions { WriteIndented = true };
            return JsonSerializer.Serialize(this, options);
        }

        public DomainHealthCheck FilterAnalyses(IEnumerable<HealthCheckType> healthCheckTypes) {
            var active = healthCheckTypes != null
                ? new HashSet<HealthCheckType>(healthCheckTypes)
                : new HashSet<HealthCheckType>();
            var clone = (DomainHealthCheck)MemberwiseClone();

            if (!active.Contains(HealthCheckType.DMARC)) {
                clone.DmarcAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.SPF)) {
                clone.SpfAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.DKIM)) {
                clone.DKIMAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.MX)) {
                clone.MXAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.CAA)) {
                clone.CAAAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.NS)) {
                clone.NSAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.DANE)) {
                clone.DaneAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.DNSBL)) {
                clone.DNSBLAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.DNSSEC)) {
                clone.DNSSecAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.MTASTS)) {
                clone.MTASTSAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.TLSRPT)) {
                clone.TLSRPTAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.BIMI)) {
                clone.BimiAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.CERT)) {
                clone.CertificateAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.SECURITYTXT)) {
                clone.SecurityTXTAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.SOA)) {
                clone.SOAAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.OPENRELAY)) {
                clone.OpenRelayAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.STARTTLS)) {
                clone.StartTlsAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.SMTPTLS)) {
                clone.SmtpTlsAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.HTTP)) {
                clone.HttpAnalysis = null;
            }
            if (!active.Contains(HealthCheckType.HPKP)) {
                clone.HPKPAnalysis = null;
            }

            return clone;
        }
    }
}