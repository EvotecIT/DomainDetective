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

        // Settings properties moved to DomainHealthCheck.Settings.cs

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

        // Settings properties moved to DomainHealthCheck.Settings.cs

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

    }
}