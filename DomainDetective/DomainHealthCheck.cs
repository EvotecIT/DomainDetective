using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
        private readonly PublicSuffixList _publicSuffixList;

        /// <summary>
        /// Indicates whether the last verified domain is itself a public suffix.
        /// </summary>
        public bool IsPublicSuffix { get; private set; }

        private void UpdateIsPublicSuffix(string domainName) {
            IsPublicSuffix = _publicSuffixList.IsPublicSuffix(domainName);
        }
        /// <summary>
        /// DNS server used when querying records.
        /// </summary>
        /// <value>The endpoint for DNS queries.</value>
        public DnsEndpoint DnsEndpoint {
            get => DnsConfiguration.DnsEndpoint;
            set {
                _logger.WriteVerbose("Setting DnsEndpoint to {0}", value);
                DnsConfiguration.DnsEndpoint = value;
            }
        }

        /// <summary>
        /// Strategy for choosing the DNS server when multiple are configured.
        /// </summary>
        /// <value>The selection strategy.</value>
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

        /// <summary>
        /// Gets the DKIM analysis.
        /// </summary>
        /// <value>Results of DKIM validation.</value>
        public DkimAnalysis DKIMAnalysis { get; private set; } = new DkimAnalysis();

        /// <summary>
        /// Gets the MX record analysis.
        /// </summary>
        /// <value>Details about mail exchanger configuration.</value>
        public MXAnalysis MXAnalysis { get; private set; }

        /// <summary>
        /// Gets the CAA analysis.
        /// </summary>
        /// <value>Certificate authority authorization results.</value>
        public CAAAnalysis CAAAnalysis { get; private set; } = new CAAAnalysis();

        /// <summary>
        /// Gets the NS analysis.
        /// </summary>
        /// <value>Name server configuration results.</value>
        public NSAnalysis NSAnalysis { get; private set; } = new NSAnalysis();

        /// <summary>
        /// Gets the DANE analysis.
        /// </summary>
        /// <value>DANE records and validation output.</value>
        public DANEAnalysis DaneAnalysis { get; private set; } = new DANEAnalysis();

        /// <summary>
        /// Gets the DNS block list analysis.
        /// </summary>
        /// <value>DNSBL lookup results.</value>
        public DNSBLAnalysis DNSBLAnalysis { get; private set; }

        /// <summary>
        /// Gets the DNSSEC analysis.
        /// </summary>
        /// <value>Information about DNSSEC chain validity.</value>
        public DNSSecAnalysis DNSSecAnalysis { get; private set; } = new DNSSecAnalysis();

        /// <summary>
        /// Gets the MTA-STS analysis.
        /// </summary>
        /// <value>SMTP MTA-STS policy results.</value>
        public MTASTSAnalysis MTASTSAnalysis { get; private set; } = new MTASTSAnalysis();

        /// <summary>
        /// Optional override for the MTA-STS policy URL.
        /// </summary>
        /// <value>A URL to use instead of querying DNS.</value>
        public string MtaStsPolicyUrlOverride { get; set; }

        /// <summary>
        /// Gets the TLS certificate analysis.
        /// </summary>
        /// <value>Results of certificate checks.</value>
        public CertificateAnalysis CertificateAnalysis { get; private set; } = new CertificateAnalysis();

        /// <summary>
        /// Gets the security.txt analysis.
        /// </summary>
        /// <value>Information from discovered security.txt files.</value>
        public SecurityTXTAnalysis SecurityTXTAnalysis { get; private set; } = new SecurityTXTAnalysis();

        /// <summary>
        /// Gets the SOA analysis.
        /// </summary>
        /// <value>Start of authority record details.</value>
        public SOAAnalysis SOAAnalysis { get; private set; } = new SOAAnalysis();

        /// <summary>
        /// Gets the WHOIS analysis.
        /// </summary>
        /// <value>Parsed WHOIS information.</value>
        public WhoisAnalysis WhoisAnalysis { get; private set; } = new WhoisAnalysis();

        /// <summary>
        /// Gets the open relay analysis.
        /// </summary>
        /// <value>SMTP relay test results.</value>
        public OpenRelayAnalysis OpenRelayAnalysis { get; private set; } = new OpenRelayAnalysis();

        /// <summary>
        /// Gets the STARTTLS analysis.
        /// </summary>
        /// <value>Information from STARTTLS negotiations.</value>
        public STARTTLSAnalysis StartTlsAnalysis { get; private set; } = new STARTTLSAnalysis();

        /// <summary>
        /// Gets the SMTP TLS analysis.
        /// </summary>
        /// <value>Results of SMTP TLS capability checks.</value>
        public SMTPTLSAnalysis SmtpTlsAnalysis { get; private set; } = new SMTPTLSAnalysis();

        /// <summary>
        /// Gets the TLSRPT analysis.
        /// </summary>
        /// <value>Reports about TLS failures.</value>
        public TLSRPTAnalysis TLSRPTAnalysis { get; private set; } = new TLSRPTAnalysis();

        /// <summary>
        /// Gets the BIMI analysis.
        /// </summary>
        /// <value>Brand Indicators for Message Identification results.</value>
        public BimiAnalysis BimiAnalysis { get; private set; } = new BimiAnalysis();

        /// <summary>
        /// Gets the HTTP analysis.
        /// </summary>
        /// <value>HTTP endpoint validation results.</value>
        public HttpAnalysis HttpAnalysis { get; private set; } = new HttpAnalysis();

        /// <summary>
        /// Gets the HPKP analysis.
        /// </summary>
        /// <value>Deprecated HTTP public key pinning information.</value>
        public HPKPAnalysis HPKPAnalysis { get; private set; } = new HPKPAnalysis();

        /// <summary>
        /// Gets the contact TXT analysis.
        /// </summary>
        /// <value>Parsed contact information.</value>
        public ContactInfoAnalysis ContactInfoAnalysis { get; private set; } = new ContactInfoAnalysis();


        /// <summary>
        /// Holds DNS client configuration used throughout analyses.
        /// </summary>
        /// <value>The DNS configuration instance.</value>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>
        /// Initializes a new instance of the <see cref="DomainHealthCheck"/> class.
        /// </summary>
        /// <param name="dnsEndpoint">
        /// <para>DNS server to use for queries. Defaults to Cloudflare.</para>
        /// </param>
        /// <param name="internalLogger">
        /// <para>Optional logger for diagnostic output.</para>
        /// </param>
        public DomainHealthCheck(DnsEndpoint dnsEndpoint = DnsEndpoint.CloudflareWireFormat, InternalLogger internalLogger = null) {
            if (internalLogger != null) {
                _logger = internalLogger;
            }
            DnsEndpoint = dnsEndpoint;
            DnsSelectionStrategy = DnsSelectionStrategy.First;

            var listPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat");
            _publicSuffixList = PublicSuffixList.Load(listPath);

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

        /// <summary>
        /// Verifies DKIM records for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to inspect.</param>
        /// <param name="selectors">Selectors to query or <c>null</c> to auto detect.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
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

        /// <summary>
        /// Runs the requested health checks against a domain.
        /// </summary>
        /// <param name="domainName">Domain to validate.</param>
        /// <param name="healthCheckTypes">Health checks to execute or <c>null</c> for defaults.</param>
        /// <param name="dkimSelectors">DKIM selectors to use when verifying DKIM.</param>
        /// <param name="daneServiceType">DANE service types to inspect.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null, ServiceType[] daneServiceType = null, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
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

            healthCheckTypes = healthCheckTypes.Distinct().ToArray();

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
                        await StartTlsAnalysis.AnalyzeServers(tlsHosts, new[] { 25 }, _logger, cancellationToken);
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
                    case HealthCheckType.CONTACT:
                        ContactInfoAnalysis = new ContactInfoAnalysis();
                        var contact = await DnsConfiguration.QueryDNS("contact." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
                        await ContactInfoAnalysis.AnalyzeContactRecords(contact, _logger);
                        break;
                    default:
                        _logger.WriteError("Unknown health check type: {0}", healthCheckType);
                        throw new NotSupportedException("Health check type not implemented.");
                }
            }
        }

        /// <summary>
        /// Analyzes a raw DMARC record.
        /// </summary>
        /// <param name="dmarcRecord">DMARC record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDMARC(string dmarcRecord, CancellationToken cancellationToken = default) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dmarcRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes a raw SPF record.
        /// </summary>
        /// <param name="spfRecord">SPF record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSPF(string spfRecord, CancellationToken cancellationToken = default) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = spfRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes a raw DKIM record.
        /// </summary>
        /// <param name="dkimRecord">DKIM record text.</param>
        /// <param name="selector">Selector associated with the record.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDKIM(string dkimRecord, string selector = "default", CancellationToken cancellationToken = default) {
            DKIMAnalysis.Reset();
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dkimRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes a raw MX record.
        /// </summary>
        /// <param name="mxRecord">MX record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckMX(string mxRecord, CancellationToken cancellationToken = default) {
            await MXAnalysis.AnalyzeMxRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = mxRecord,
                    Type = DnsRecordType.MX
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes a single CAA record.
        /// </summary>
        /// <param name="caaRecord">CAA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckCAA(string caaRecord, CancellationToken cancellationToken = default) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = caaRecord,
                    Type = DnsRecordType.CAA
                }
            }, _logger);
        }
        /// <summary>
        /// Analyzes multiple CAA records.
        /// </summary>
        /// <param name="caaRecords">Collection of CAA record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckCAA(List<string> caaRecords, CancellationToken cancellationToken = default) {
            var dnsResults = caaRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }

        /// <summary>
        /// Analyzes a single NS record.
        /// </summary>
        /// <param name="nsRecord">NS record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckNS(string nsRecord, CancellationToken cancellationToken = default) {
            await NSAnalysis.AnalyzeNsRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = nsRecord,
                    Type = DnsRecordType.NS
                }
            }, _logger);
        }
        /// <summary>
        /// Analyzes multiple NS records.
        /// </summary>
        /// <param name="nsRecords">Collection of NS record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckNS(List<string> nsRecords, CancellationToken cancellationToken = default) {
            var dnsResults = nsRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();
            await NSAnalysis.AnalyzeNsRecords(dnsResults, _logger);
        }

        /// <summary>
        /// Analyzes a single DANE record.
        /// </summary>
        /// <param name="daneRecord">TLSA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDANE(string daneRecord, CancellationToken cancellationToken = default) {
            await DaneAnalysis.AnalyzeDANERecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = daneRecord
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes a raw SOA record.
        /// </summary>
        /// <param name="soaRecord">SOA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSOA(string soaRecord, CancellationToken cancellationToken = default) {
            await SOAAnalysis.AnalyzeSoaRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = soaRecord,
                    Type = DnsRecordType.SOA
                }
            }, _logger);
        }

        /// <summary>
        /// Tests an SMTP server for open relay configuration.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckOpenRelayHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await OpenRelayAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for STARTTLS support.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckStartTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await StartTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for SMTP TLS capabilities.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSmtpTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            await SmtpTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Analyzes a raw TLSRPT record.
        /// </summary>
        /// <param name="tlsRptRecord">TLSRPT record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckTLSRPT(string tlsRptRecord, CancellationToken cancellationToken = default) {
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = tlsRptRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken);
        }

        /// <summary>
        /// Analyzes a raw BIMI record.
        /// </summary>
        /// <param name="bimiRecord">BIMI record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckBIMI(string bimiRecord, CancellationToken cancellationToken = default) {
            await BimiAnalysis.AnalyzeBimiRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = bimiRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken);
        }

        /// <summary>
        /// Analyzes a raw contact TXT record.
        /// </summary>
        /// <param name="contactRecord">Contact record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckContactInfo(string contactRecord, CancellationToken cancellationToken = default) {
            await ContactInfoAnalysis.AnalyzeContactRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = contactRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }


        /// <summary>
        /// Queries DNS and analyzes SPF records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySPF(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1", cancellationToken);
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
        }

        /// <summary>
        /// Verifies MTA-STS policy for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyMTASTS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            MTASTSAnalysis = new MTASTSAnalysis {
                PolicyUrlOverride = MtaStsPolicyUrlOverride
            };
            await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
        }

        /// <summary>
        /// Checks all MX hosts for STARTTLS support.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="port">SMTP port to connect to.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySTARTTLS(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await StartTlsAnalysis.AnalyzeServers(tlsHosts, new[] { port }, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for SMTP TLS configuration.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySMTPTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = mxRecordsForTls.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await SmtpTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger, cancellationToken);
        }

        /// <summary>
        /// Queries and analyzes TLSRPT records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyTLSRPT(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            TLSRPTAnalysis = new TLSRPTAnalysis();
            var tlsrpt = await DnsConfiguration.QueryDNS("_smtp._tls." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger, cancellationToken);
        }

        /// <summary>
        /// Queries and analyzes BIMI records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyBIMI(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            BimiAnalysis = new BimiAnalysis();
            var bimi = await DnsConfiguration.QueryDNS($"default._bimi.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken);
        }

        /// <summary>
        /// Queries contact TXT records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyContactInfo(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            ContactInfoAnalysis = new ContactInfoAnalysis();
            var contact = await DnsConfiguration.QueryDNS("contact." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
            await ContactInfoAnalysis.AnalyzeContactRecords(contact, _logger);
        }

        /// <summary>
        /// Queries TLSA records for specific ports on a domain.
        /// </summary>
        /// <param name="domainName">Domain to query.</param>
        /// <param name="ports">Ports to check for DANE.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDANE(string domainName, int[] ports, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
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

        /// <summary>
        /// Queries TLSA records for the provided service definitions.
        /// </summary>
        /// <param name="services">Services to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
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

        /// <summary>
        /// Queries TLSA records based on common service types.
        /// </summary>
        /// <param name="domainName">Domain to query.</param>
        /// <param name="serviceTypes">Services to investigate.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDANE(string domainName, ServiceType[] serviceTypes, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
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

        /// <summary>
        /// Performs a basic HTTP check without enforcing HTTPS.
        /// </summary>
        /// <param name="domainName">Domain or host to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyPlainHttp(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            await HttpAnalysis.AnalyzeUrl($"http://{domainName}", false, _logger);
        }

        /// <summary>
        /// Checks an IP address against configured DNS block lists.
        /// </summary>
        /// <param name="ipAddress">IP address to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDNSBL(string ipAddress, CancellationToken cancellationToken = default) {
            await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ipAddress, _logger)) {
                // enumeration triggers processing
            }
        }

        /// <summary>
        /// Checks multiple IP addresses against DNS block lists.
        /// </summary>
        /// <param name="ipAddresses">IPs to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDNSBL(string[] ipAddresses, CancellationToken cancellationToken = default) {
            foreach (var ip in ipAddresses) {
                await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ip, _logger)) {
                    // enumeration triggers processing
                }
            }
        }

        /// <summary>
        /// Queries WHOIS information for a domain.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckWHOIS(string domain, CancellationToken cancellationToken = default) {
            var timeout = WhoisAnalysis.Timeout;
            WhoisAnalysis = new WhoisAnalysis { Timeout = timeout };
            UpdateIsPublicSuffix(domain);
            await WhoisAnalysis.QueryWhoisServer(domain, cancellationToken);
        }

        /// <summary>
        /// Creates a high level summary of key analyses.
        /// </summary>
        /// <returns>A populated <see cref="DomainSummary"/>.</returns>
        public DomainSummary BuildSummary() {
            var spfValid = SpfAnalysis.SpfRecordExists && SpfAnalysis.StartsCorrectly &&
                            !SpfAnalysis.ExceedsDnsLookups && !SpfAnalysis.MultipleSpfRecords;

            var dmarcValid = DmarcAnalysis.DmarcRecordExists && DmarcAnalysis.StartsCorrectly &&
                             DmarcAnalysis.HasMandatoryTags && DmarcAnalysis.IsPolicyValid &&
                             DmarcAnalysis.IsPctValid && !DmarcAnalysis.MultipleRecords &&
                             !DmarcAnalysis.ExceedsCharacterLimit && DmarcAnalysis.ValidDkimAlignment &&
                             DmarcAnalysis.ValidSpfAlignment;

            var dkimValid = DKIMAnalysis.AnalysisResults.Values.Any(a =>
                a.DkimRecordExists && a.StartsCorrectly && a.PublicKeyExists &&
                a.ValidPublicKey && a.KeyTypeExists && a.ValidKeyType && a.ValidFlags);

            return new DomainSummary {
                HasSpfRecord = SpfAnalysis.SpfRecordExists,
                SpfValid = spfValid,
                HasDmarcRecord = DmarcAnalysis.DmarcRecordExists,
                DmarcPolicy = DmarcAnalysis.Policy,
                DmarcValid = dmarcValid,
                HasDkimRecord = DKIMAnalysis.AnalysisResults.Values.Any(a => a.DkimRecordExists),
                DkimValid = dkimValid,
                HasMxRecord = MXAnalysis.MxRecordExists,
                DnsSecValid = DNSSecAnalysis?.ChainValid ?? false
            };
        }
          
        /// <summary>Serializes this instance to a JSON string.</summary>
        /// <param name="options">
        /// <para>Optional serializer options. If not provided,</para>
        /// <para><see cref="JsonSerializerOptions.WriteIndented"/> is enabled.</para>
        /// </param>
        /// <returns>
        /// <para>A JSON representation of the current
        /// <see cref="DomainHealthCheck"/>.</para>
        /// </returns>
        public string ToJson(JsonSerializerOptions options = null) {
            options ??= new JsonSerializerOptions { WriteIndented = true };
            return JsonSerializer.Serialize(this, options);
        }

        /// <summary>Creates a copy with only the specified analyses included.</summary>
        /// <param name="healthCheckTypes">
        /// <para>Health checks that should remain in the returned
        /// <see cref="DomainHealthCheck"/>.</para>
        /// </param>
        /// <returns>
        /// <para>A clone of this object with non-selected analyses removed.</para>
        /// </returns>
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
            if (!active.Contains(HealthCheckType.CONTACT)) {
                clone.ContactInfoAnalysis = null;
            }

            return clone;
        }
    }
}