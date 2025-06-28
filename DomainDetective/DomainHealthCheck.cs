using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using System.Reflection;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
        private readonly PublicSuffixList _publicSuffixList;

        /// <summary>
        /// Indicates whether the last verified domain is itself a public suffix.
        /// </summary>
        public bool IsPublicSuffix { get; private set; }

        /// <summary>
        /// When true, DMARC policy strength evaluation checks the <c>sp</c> tag.
        /// </summary>
        public bool UseSubdomainPolicy { get; set; }

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
        /// Gets the reverse DNS analysis for MX hosts.
        /// </summary>
        /// <value>PTR lookup results for mail exchangers.</value>
        public ReverseDnsAnalysis ReverseDnsAnalysis { get; private set; } = new ReverseDnsAnalysis();

        /// <summary>Gets the forward-confirmed reverse DNS analysis.</summary>
        /// <value>Results verifying PTR hostnames resolve back to their IP.</value>
        public FCrDnsAnalysis FCrDnsAnalysis { get; private set; } = new FCrDnsAnalysis();

        /// <summary>Alias used by <see cref="GetAnalysisMap"/>.</summary>
        public FCrDnsAnalysis FCRDNSAnalysis => FCrDnsAnalysis;

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

        /// <summary>API key for Google Safe Browsing.</summary>
        public string? GoogleSafeBrowsingApiKey { get; set; }

        /// <summary>API key for PhishTank.</summary>
        public string? PhishTankApiKey { get; set; }

        /// <summary>API key for VirusTotal.</summary>
        public string? VirusTotalApiKey { get; set; }

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
        /// Gets the zone transfer analysis.
        /// </summary>
        /// <value>AXFR test results per name server.</value>
        public ZoneTransferAnalysis ZoneTransferAnalysis { get; private set; } = new ZoneTransferAnalysis();

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
        /// Gets the SMTP banner analysis.
        /// </summary>
        /// <value>Initial greetings from SMTP servers.</value>
        public SMTPBannerAnalysis SmtpBannerAnalysis { get; private set; } = new SMTPBannerAnalysis();

        /// <summary>
        /// Gets the SMTP AUTH analysis.
        /// </summary>
        /// <value>Advertised authentication mechanisms.</value>
        public SmtpAuthAnalysis SmtpAuthAnalysis { get; private set; } = new SmtpAuthAnalysis();

        /// <summary>Alias used by <see cref="GetAnalysisMap"/>.</summary>
        public SmtpAuthAnalysis SMTPAUTHAnalysis => SmtpAuthAnalysis;

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
        /// Gets the Autodiscover analysis.
        /// </summary>
        /// <value>Results of Autodiscover related checks.</value>
        public AutodiscoverAnalysis AutodiscoverAnalysis { get; private set; } = new AutodiscoverAnalysis();

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
        /// Gets the message header analysis.
        /// </summary>
        /// <value>Details parsed from message headers.</value>
        public MessageHeaderAnalysis MessageHeaderAnalysis { get; private set; } = new MessageHeaderAnalysis();

        /// <summary>
        /// Gets the ARC header analysis.
        /// </summary>
        /// <value>Results from ARC chain validation.</value>
        public ARCAnalysis ArcAnalysis { get; private set; } = new ARCAnalysis();

        /// <summary>
        /// Gets the dangling CNAME analysis.
        /// </summary>
        /// <value>Information about unresolved CNAME targets.</value>
        public DanglingCnameAnalysis DanglingCnameAnalysis { get; private set; } = new DanglingCnameAnalysis();

        /// Gets DNS TTL analysis.
        /// </summary>
        /// <value>Information about record TTL values.</value>
        public DnsTtlAnalysis DnsTtlAnalysis { get; private set; } = new DnsTtlAnalysis();

        /// <summary>
        /// Gets the port availability analysis.
        /// </summary>
        /// <value>TCP port connectivity results.</value>
        public PortAvailabilityAnalysis PortAvailabilityAnalysis { get; private set; } = new PortAvailabilityAnalysis();

        /// <summary>Gets the IP neighbor analysis.</summary>
        /// <value>Domains sharing the same IP address.</value>
        public IPNeighborAnalysis IPNeighborAnalysis { get; private set; } = new IPNeighborAnalysis();

        /// <summary>Gets the DNS tunneling analysis.</summary>
        /// <value>Possible tunneling activities.</value>
        public DnsTunnelingAnalysis DnsTunnelingAnalysis { get; private set; } = new DnsTunnelingAnalysis();

        /// <summary>Gets the typosquatting analysis.</summary>
        /// <value>Potential look-alike domains.</value>
        public TyposquattingAnalysis TyposquattingAnalysis { get; private set; } = new TyposquattingAnalysis();

        /// <summary>Gets the threat intelligence analysis.</summary>
        /// <value>Results from reputation services.</value>
        public ThreatIntelAnalysis ThreatIntelAnalysis { get; private set; } = new ThreatIntelAnalysis();
        /// <summary>Alias used by <see cref="GetAnalysisMap"/>.</summary>
        public ThreatIntelAnalysis THREATINTELAnalysis => ThreatIntelAnalysis;

        /// <summary>Log lines used for DNS tunneling analysis.</summary>
        public IEnumerable<string>? DnsTunnelingLogs { get; set; }

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

            var preloadPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hsts_preload.json");
            if (File.Exists(preloadPath)) {
                HttpAnalysis.LoadHstsPreloadList(preloadPath);
            }

            DmarcAnalysis.DnsConfiguration = DnsConfiguration;

            SpfAnalysis = new SpfAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            MXAnalysis = new MXAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            ReverseDnsAnalysis.DnsConfiguration = DnsConfiguration;
            FCrDnsAnalysis.DnsConfiguration = DnsConfiguration;

            NSAnalysis = new NSAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            ZoneTransferAnalysis = new ZoneTransferAnalysis();

            DNSBLAnalysis = new DNSBLAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            MTASTSAnalysis = new MTASTSAnalysis() {
                DnsConfiguration = DnsConfiguration
            };

            DanglingCnameAnalysis.DnsConfiguration = DnsConfiguration;

            DnsTtlAnalysis = new DnsTtlAnalysis {
                DnsConfiguration = DnsConfiguration
            };

            PortAvailabilityAnalysis = new PortAvailabilityAnalysis();

            IPNeighborAnalysis.DnsConfiguration = DnsConfiguration;
            DnsTunnelingAnalysis = new DnsTunnelingAnalysis();
            TyposquattingAnalysis.DnsConfiguration = DnsConfiguration;

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
                cancellationToken.ThrowIfCancellationRequested();
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
        /// <param name="daneServiceType">DANE service types to inspect. When <c>null</c>, SMTP and HTTPS (port 443) are queried.</param>
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
                    HealthCheckType.DNSBL,
                    HealthCheckType.MESSAGEHEADER
                };
            }

            healthCheckTypes = healthCheckTypes.Distinct().ToArray();

            foreach (var healthCheckType in healthCheckTypes) {
                cancellationToken.ThrowIfCancellationRequested();
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await DnsConfiguration.QueryDNS("_dmarc." + domainName, DnsRecordType.TXT, "DMARC1", cancellationToken);
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger, domainName);
                        DmarcAnalysis.EvaluatePolicyStrength(UseSubdomainPolicy);
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
                            cancellationToken.ThrowIfCancellationRequested();
                            var dkim = await DnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1", cancellationToken);
                            await DKIMAnalysis.AnalyzeDkimRecords(selector, dkim, _logger);
                        }
                        break;
                    case HealthCheckType.MX:
                        var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        await MXAnalysis.AnalyzeMxRecords(mx, _logger);
                        break;
                    case HealthCheckType.REVERSEDNS:
                        var mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var rdnsHosts = mxRecords
                            .Select(r => r.Data.Split(' ')[1].Trim('.'))
                            .Where(h => !string.IsNullOrWhiteSpace(h));
                        await ReverseDnsAnalysis.AnalyzeHosts(rdnsHosts, _logger);
                        await FCrDnsAnalysis.Analyze(ReverseDnsAnalysis.Results, _logger);
                        break;
                    case HealthCheckType.FCRDNS:
                        var mxRecordsFcr = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var rdnsHostsFcr = mxRecordsFcr
                            .Select(r => r.Data.Split(' ')[1].Trim('.'))
                            .Where(h => !string.IsNullOrWhiteSpace(h));
                        await ReverseDnsAnalysis.AnalyzeHosts(rdnsHostsFcr, _logger);
                        await FCrDnsAnalysis.Analyze(ReverseDnsAnalysis.Results, _logger);
                        break;
                    case HealthCheckType.CAA:
                        var caa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.CAA, cancellationToken: cancellationToken);
                        await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
                        break;
                    case HealthCheckType.NS:
                        var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
                        await NSAnalysis.AnalyzeNsRecords(ns, _logger);
                        break;
                    case HealthCheckType.DELEGATION:
                        await VerifyDelegation(domainName, cancellationToken);
                        break;
                    case HealthCheckType.ZONETRANSFER:
                        var nsRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
                        var servers = nsRecords.Select(r => r.Data.Trim('.'));
                        await ZoneTransferAnalysis.AnalyzeServers(domainName, servers, _logger, cancellationToken);
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
                            PolicyUrlOverride = MtaStsPolicyUrlOverride,
                            DnsConfiguration = DnsConfiguration
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
                        await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken: cancellationToken);
                        break;
                    case HealthCheckType.AUTODISCOVER:
                        AutodiscoverAnalysis = new AutodiscoverAnalysis();
                        await AutodiscoverAnalysis.Analyze(domainName, DnsConfiguration, _logger, cancellationToken);
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
                            cancellationToken.ThrowIfCancellationRequested();
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
                    case HealthCheckType.SMTPBANNER:
                        var mxRecordsForBanner = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var bannerHosts = mxRecordsForBanner.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        await SmtpBannerAnalysis.AnalyzeServers(bannerHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.SMTPAUTH:
                        var mxRecordsForAuth = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var authHosts = mxRecordsForAuth.Select(r => r.Data.Split(' ')[1].Trim('.'));
                        await SmtpAuthAnalysis.AnalyzeServers(authHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.HTTP:
                        await HttpAnalysis.AnalyzeUrl($"http://{domainName}", true, _logger, cancellationToken: cancellationToken);
                        break;
                    case HealthCheckType.HPKP:
                        await HPKPAnalysis.AnalyzeUrl($"http://{domainName}", _logger);
                        break;
                    case HealthCheckType.CONTACT:
                        ContactInfoAnalysis = new ContactInfoAnalysis();
                        var contact = await DnsConfiguration.QueryDNS("contact." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
                        await ContactInfoAnalysis.AnalyzeContactRecords(contact, _logger);
                        break;
                    case HealthCheckType.MESSAGEHEADER:
                        MessageHeaderAnalysis = CheckMessageHeaders(string.Empty, cancellationToken);
                        break;
                    case HealthCheckType.DANGLINGCNAME:
                        await DanglingCnameAnalysis.Analyze(domainName, _logger, cancellationToken);
                        break;
                    case HealthCheckType.TTL:
                        await DnsTtlAnalysis.Analyze(domainName, _logger);
                        break;
                    case HealthCheckType.PORTAVAILABILITY:
                        await CheckPortAvailability(domainName, null, cancellationToken);
                        break;
                    case HealthCheckType.IPNEIGHBOR:
                        await CheckIPNeighbors(domainName, cancellationToken);
                        break;
                    case HealthCheckType.DNSTUNNELING:
                        CheckDnsTunneling(domainName);
                        break;
                    case HealthCheckType.TYPOSQUATTING:
                        await VerifyTyposquatting(domainName, cancellationToken);
                        break;
                    case HealthCheckType.THREATINTEL:
                        await VerifyThreatIntel(domainName, cancellationToken);
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
            DmarcAnalysis.EvaluatePolicyStrength(UseSubdomainPolicy);
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
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckOpenRelayHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await OpenRelayAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for STARTTLS support.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckStartTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await StartTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for SMTP TLS capabilities.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSmtpTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await SmtpTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Retrieves the SMTP banner from a host.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSmtpBannerHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await SmtpBannerAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Tests connectivity to common service ports on a host.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="ports">Ports to check. Defaults to common services.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckPortAvailability(string host, IEnumerable<int>? ports = null, CancellationToken cancellationToken = default) {
            var list = ports?.ToArray() ?? new[] { 25, 80, 443, 465, 587 };
            foreach (var p in list) {
                ValidatePort(p);
            }
            await PortAvailabilityAnalysis.AnalyzeServers(new[] { host }, list, _logger, cancellationToken);
        }

        /// <summary>Queries neighbors sharing the same IP as <paramref name="domainName"/>.</summary>
        public async Task CheckIPNeighbors(string domainName, CancellationToken cancellationToken = default) {
            await IPNeighborAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>Analyzes DNS logs for tunneling patterns.</summary>
        public void CheckDnsTunneling(string domainName) {
            var lines = DnsTunnelingLogs ?? Array.Empty<string>();
            DnsTunnelingAnalysis.Analyze(domainName, lines);
        }

        /// <summary>
        /// Generates typosquatting variants and checks if they resolve.
        /// </summary>
        /// <param name="domainName">Domain to analyze.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyTyposquatting(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            TyposquattingAnalysis.DnsConfiguration = DnsConfiguration;
            await TyposquattingAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>Queries reputation services for threat listings.</summary>
        public async Task VerifyThreatIntel(string target, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(target)) {
                throw new ArgumentNullException(nameof(target));
            }
            UpdateIsPublicSuffix(target);
            await ThreatIntelAnalysis.Analyze(target, GoogleSafeBrowsingApiKey, PhishTankApiKey, VirusTotalApiKey, _logger, cancellationToken);
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
            }, _logger, cancellationToken: cancellationToken);
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
        /// Parses raw message headers.
        /// </summary>
        /// <param name="rawHeaders">Unparsed header text.</param>
        /// <param name="ct">Token to cancel the operation.</param>
        /// <returns>Populated <see cref="MessageHeaderAnalysis"/> instance.</returns>
        public MessageHeaderAnalysis CheckMessageHeaders(string rawHeaders, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();

            var analysis = new MessageHeaderAnalysis();
            analysis.Parse(rawHeaders, _logger);
            return analysis;
        }

        /// <summary>
        /// Validates ARC headers contained in <paramref name="rawHeaders"/>.
        /// </summary>
        /// <param name="rawHeaders">Raw message headers.</param>
        /// <param name="ct">Token to cancel the operation.</param>
        /// <returns>Populated <see cref="ARCAnalysis"/> instance.</returns>
        public ARCAnalysis VerifyARC(string rawHeaders, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            ArcAnalysis = new ARCAnalysis();
            ArcAnalysis.Analyze(rawHeaders, _logger);
            return ArcAnalysis;
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
                PolicyUrlOverride = MtaStsPolicyUrlOverride,
                DnsConfiguration = DnsConfiguration
            };
            await MTASTSAnalysis.AnalyzePolicy(domainName, _logger);
        }

        /// <summary>
        /// Checks all MX hosts for STARTTLS support.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="port">SMTP port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySTARTTLS(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
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
        /// Collects SMTP banners from all MX hosts.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="port">SMTP port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySMTPBanner(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = mx.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await SmtpBannerAnalysis.AnalyzeServers(hosts, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Retrieves SMTP AUTH capabilities from all MX hosts.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="port">SMTP port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySmtpAuth(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = mx.Select(r => r.Data.Split(' ')[1].Trim('.'));
            await SmtpAuthAnalysis.AnalyzeServers(hosts, port, _logger, cancellationToken);
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
            await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken: cancellationToken);
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

        /// Attempts zone transfers against authoritative name servers.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyZoneTransfer(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            var nsRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            var servers = nsRecords.Select(r => r.Data.Trim('.'));
            await ZoneTransferAnalysis.AnalyzeServers(domainName, servers, _logger, cancellationToken);
        }

        /// <summary>
        /// Validates delegation information against the parent zone.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDelegation(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            UpdateIsPublicSuffix(domainName);
            var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            await NSAnalysis.AnalyzeNsRecords(ns, _logger);
            await NSAnalysis.AnalyzeParentDelegation(domainName, _logger);
        }

        /// <summary>
        /// Detects dangling CNAME records for the domain.
        /// </summary>
        public async Task VerifyDanglingCname(string domainName, CancellationToken cancellationToken = default) {
            DanglingCnameAnalysis = new DanglingCnameAnalysis { DnsConfiguration = DnsConfiguration };
            await DanglingCnameAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// Queries Autodiscover related records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyAutodiscover(string domainName, CancellationToken cancellationToken = default) {
            AutodiscoverAnalysis = new AutodiscoverAnalysis();
            await AutodiscoverAnalysis.Analyze(domainName, DnsConfiguration, _logger, cancellationToken);
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
                cancellationToken.ThrowIfCancellationRequested();
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
                cancellationToken.ThrowIfCancellationRequested();
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
                        throw new System.Exception("Service type not implemented.");
                }

                var recordData = records.Select(x => x.Data ?? x.DataRaw).Distinct();
                foreach (var record in recordData) {
                    cancellationToken.ThrowIfCancellationRequested();
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
        /// <param name="port">Port to use for the connection. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        public async Task VerifyWebsiteCertificate(string url, int port = 443, CancellationToken cancellationToken = default) {
            ValidatePort(port);
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
            await HttpAnalysis.AnalyzeUrl($"http://{domainName}", false, _logger, cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Checks an IP address against configured DNS block lists.
        /// </summary>
        /// <param name="ipAddress">IP address to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDNSBL(string ipAddress, CancellationToken cancellationToken = default) {
            await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ipAddress, _logger)) {
                cancellationToken.ThrowIfCancellationRequested();
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
                cancellationToken.ThrowIfCancellationRequested();
                await foreach (var _ in DNSBLAnalysis.AnalyzeDNSBLRecords(ip, _logger)) {
                    cancellationToken.ThrowIfCancellationRequested();
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
                DnsSecValid = DNSSecAnalysis?.ChainValid ?? false,
                ExpiryDate = WhoisAnalysis.ExpiryDate,
                ExpiresSoon = WhoisAnalysis.ExpiresSoon,
                IsExpired = WhoisAnalysis.IsExpired,
                RegistrarLocked = WhoisAnalysis.RegistrarLocked
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

        private static void ValidatePort(int port) {
            if (port <= 0 || port > 65535) {
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");
            }
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

            var filtered = new DomainHealthCheck(DnsEndpoint, _logger) {
                DnsSelectionStrategy = DnsSelectionStrategy,
                DnsConfiguration = DnsConfiguration,
                MtaStsPolicyUrlOverride = MtaStsPolicyUrlOverride
            };

            filtered.DmarcAnalysis = active.Contains(HealthCheckType.DMARC) ? CloneAnalysis(DmarcAnalysis) : null;
            filtered.SpfAnalysis = active.Contains(HealthCheckType.SPF) ? CloneAnalysis(SpfAnalysis) : null;
            filtered.DKIMAnalysis = active.Contains(HealthCheckType.DKIM) ? CloneAnalysis(DKIMAnalysis) : null;
            filtered.MXAnalysis = active.Contains(HealthCheckType.MX) ? CloneAnalysis(MXAnalysis) : null;
            filtered.ReverseDnsAnalysis = active.Contains(HealthCheckType.REVERSEDNS) ? CloneAnalysis(ReverseDnsAnalysis) : null;
            filtered.FCrDnsAnalysis = active.Contains(HealthCheckType.FCRDNS) ? CloneAnalysis(FCrDnsAnalysis) : null;
            filtered.CAAAnalysis = active.Contains(HealthCheckType.CAA) ? CloneAnalysis(CAAAnalysis) : null;
            filtered.NSAnalysis =
                active.Contains(HealthCheckType.NS) || active.Contains(HealthCheckType.DELEGATION)
                    ? CloneAnalysis(NSAnalysis)
                    : null;
            filtered.ZoneTransferAnalysis = active.Contains(HealthCheckType.ZONETRANSFER) ? CloneAnalysis(ZoneTransferAnalysis) : null;
            filtered.DaneAnalysis = active.Contains(HealthCheckType.DANE) ? CloneAnalysis(DaneAnalysis) : null;
            filtered.DNSBLAnalysis = active.Contains(HealthCheckType.DNSBL) ? CloneAnalysis(DNSBLAnalysis) : null;
            filtered.DNSSecAnalysis = active.Contains(HealthCheckType.DNSSEC) ? CloneAnalysis(DNSSecAnalysis) : null;
            filtered.MTASTSAnalysis = active.Contains(HealthCheckType.MTASTS) ? CloneAnalysis(MTASTSAnalysis) : null;
            filtered.TLSRPTAnalysis = active.Contains(HealthCheckType.TLSRPT) ? CloneAnalysis(TLSRPTAnalysis) : null;
            filtered.BimiAnalysis = active.Contains(HealthCheckType.BIMI) ? CloneAnalysis(BimiAnalysis) : null;
            filtered.AutodiscoverAnalysis = active.Contains(HealthCheckType.AUTODISCOVER) ? CloneAnalysis(AutodiscoverAnalysis) : null;
            filtered.CertificateAnalysis = active.Contains(HealthCheckType.CERT) ? CloneAnalysis(CertificateAnalysis) : null;
            filtered.SecurityTXTAnalysis = active.Contains(HealthCheckType.SECURITYTXT) ? CloneAnalysis(SecurityTXTAnalysis) : null;
            filtered.SOAAnalysis = active.Contains(HealthCheckType.SOA) ? CloneAnalysis(SOAAnalysis) : null;
            filtered.OpenRelayAnalysis = active.Contains(HealthCheckType.OPENRELAY) ? CloneAnalysis(OpenRelayAnalysis) : null;
            filtered.StartTlsAnalysis = active.Contains(HealthCheckType.STARTTLS) ? CloneAnalysis(StartTlsAnalysis) : null;
            filtered.SmtpTlsAnalysis = active.Contains(HealthCheckType.SMTPTLS) ? CloneAnalysis(SmtpTlsAnalysis) : null;
            filtered.SmtpBannerAnalysis = active.Contains(HealthCheckType.SMTPBANNER) ? CloneAnalysis(SmtpBannerAnalysis) : null;
            filtered.SmtpAuthAnalysis = active.Contains(HealthCheckType.SMTPAUTH) ? CloneAnalysis(SmtpAuthAnalysis) : null;
            filtered.HttpAnalysis = active.Contains(HealthCheckType.HTTP) ? CloneAnalysis(HttpAnalysis) : null;
            filtered.HPKPAnalysis = active.Contains(HealthCheckType.HPKP) ? CloneAnalysis(HPKPAnalysis) : null;
            filtered.ContactInfoAnalysis = active.Contains(HealthCheckType.CONTACT) ? CloneAnalysis(ContactInfoAnalysis) : null;
            filtered.MessageHeaderAnalysis = active.Contains(HealthCheckType.MESSAGEHEADER) ? CloneAnalysis(MessageHeaderAnalysis) : null;
            filtered.ArcAnalysis = active.Contains(HealthCheckType.ARC) ? CloneAnalysis(ArcAnalysis) : null;
            filtered.DanglingCnameAnalysis = active.Contains(HealthCheckType.DANGLINGCNAME) ? CloneAnalysis(DanglingCnameAnalysis) : null;
            filtered.DnsTtlAnalysis = active.Contains(HealthCheckType.TTL) ? CloneAnalysis(DnsTtlAnalysis) : null;
            filtered.PortAvailabilityAnalysis = active.Contains(HealthCheckType.PORTAVAILABILITY) ? CloneAnalysis(PortAvailabilityAnalysis) : null;
            filtered.IPNeighborAnalysis = active.Contains(HealthCheckType.IPNEIGHBOR) ? CloneAnalysis(IPNeighborAnalysis) : null;
            filtered.DnsTunnelingAnalysis = active.Contains(HealthCheckType.DNSTUNNELING) ? CloneAnalysis(DnsTunnelingAnalysis) : null;
            filtered.TyposquattingAnalysis = active.Contains(HealthCheckType.TYPOSQUATTING) ? CloneAnalysis(TyposquattingAnalysis) : null;
            filtered.ThreatIntelAnalysis = active.Contains(HealthCheckType.THREATINTEL) ? CloneAnalysis(ThreatIntelAnalysis) : null;

            return filtered;
        }

        private static readonly MethodInfo _cloneMethod = typeof(object).GetMethod(
            "MemberwiseClone",
            BindingFlags.Instance | BindingFlags.NonPublic);

        private static T CloneAnalysis<T>(T analysis) where T : class {
            return analysis == null ? null : (T)_cloneMethod.Invoke(analysis, null);
        }
    }
}