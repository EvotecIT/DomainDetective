using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Reflection;
using System.Linq.Expressions;
using System.Globalization;
using DomainDetective.Network;

namespace DomainDetective {
    /// <summary>
    /// Contains verification methods used by <see cref="DomainHealthCheck"/>.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class DomainHealthCheck {
        private static readonly IdnMapping _idn = new();

        private static string NormalizeDomain(string input)
        {
            return _idn.GetAscii(input.Trim().Trim('.')).ToLowerInvariant();
        }

        private static string CreateServiceQuery(int port, string domain) {
#if NET6_0_OR_GREATER
            var portString = port.ToString(CultureInfo.InvariantCulture);
            return string.Create(portString.Length + domain.Length + 7, (portString, domain), static (span, state) => {
                var (digits, host) = state;
                var pos = 0;
                span[pos++] = '_';
                digits.AsSpan().CopyTo(span[pos..]);
                pos += digits.Length;
                "._tcp.".AsSpan().CopyTo(span[pos..]);
                pos += 6;
                host.AsSpan().CopyTo(span[pos..]);
            });
#else
            return $"_{port}._tcp.{domain}";
#endif
        }

        private static void ValidateServiceQueryProtocol(string query) {
            bool hasTcp = query.IndexOf("._tcp.", StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasUdp = query.IndexOf("._udp.", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!hasTcp && !hasUdp) {
                throw new InvalidOperationException($"Invalid service query '{query}', expected _tcp or _udp suffix.");
            }
        }

        private void UpdateIsPublicSuffix(string domainName) {
            string host = domainName;
            if (Uri.TryCreate($"http://{domainName}", UriKind.Absolute, out var uri)) {
                host = uri.Host;
            } else {
                try {
                    host = _idn.GetAscii(domainName.Trim().Trim('.'));
                } catch (ArgumentException) {
                }
            }

            var ascii = NormalizeDomain(host);
            IsPublicSuffix = _publicSuffixList.IsPublicSuffix(ascii);
        }
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
            domainName = NormalizeDomain(domainName);
            if (selectors == null || selectors.Length == 0) {
                await DKIMAnalysis.QueryWellKnownSelectors(domainName, DnsConfiguration, _logger, cancellationToken);
                return;
            }

            var adsp = await DnsConfiguration.QueryDNS($"_adsp._domainkey.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await DKIMAnalysis.AnalyzeAdspRecord(adsp, _logger);
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
        /// <param name="danePorts">Custom ports to check for DANE. Overrides <paramref name="daneServiceType"/> when provided.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task Verify(string domainName, HealthCheckType[] healthCheckTypes = null, string[] dkimSelectors = null, ServiceType[] daneServiceType = null, int[] danePorts = null, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            IsPublicSuffix = false;
            domainName = ValidateHostName(domainName);
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

            var totalChecks = healthCheckTypes.Length;
            var processedChecks = 0;

            foreach (var healthCheckType in healthCheckTypes) {
                cancellationToken.ThrowIfCancellationRequested();
                _logger.WriteProgress(
                    "HealthCheck",
                    healthCheckType.ToString(),
                    processedChecks * 100d / totalChecks,
                    processedChecks,
                    totalChecks);
                switch (healthCheckType) {
                    case HealthCheckType.DMARC:
                        var dmarc = await DnsConfiguration.QueryDNS("_dmarc." + domainName, DnsRecordType.TXT, "DMARC1", cancellationToken);
                        await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger, domainName, _publicSuffixList.GetRegistrableDomain);
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

                        var adsp = await DnsConfiguration.QueryDNS($"_adsp._domainkey.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
                        if (adsp.Any()) {
                            await DKIMAnalysis.AnalyzeAdspRecord(adsp, _logger);
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
                        var rdnsHosts = CertificateAnalysis.ExtractMxHosts(mxRecords);
                        await ReverseDnsAnalysis.AnalyzeHosts(rdnsHosts, _logger);
                        break;
                    case HealthCheckType.FCRDNS:
                        var mxRecordsFcr = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        var rdnsHostsFcr = CertificateAnalysis.ExtractMxHosts(mxRecordsFcr);
                        await ReverseDnsAnalysis.AnalyzeHosts(rdnsHostsFcr, _logger);
                        await FcrDnsAnalysis.Analyze(ReverseDnsAnalysis.Results, _logger);
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
                        if (danePorts != null && danePorts.Length > 0) {
                            await VerifyDANE(domainName, danePorts, cancellationToken);
                        } else {
                            await VerifyDANE(domainName, daneServiceType, cancellationToken);
                        }
                        break;
                    case HealthCheckType.DNSSEC:
                        DnsSecAnalysis = new DnsSecAnalysis();
                        await DnsSecAnalysis.Analyze(domainName, _logger, DnsConfiguration);
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
                    case HealthCheckType.CERT:
                        await VerifyWebsiteCertificate(domainName, cancellationToken: cancellationToken);
                        break;
                    case HealthCheckType.SECURITYTXT:
                        // lets reset the SecurityTXTAnalysis, so it's overwritten completely on next run
                        SecurityTXTAnalysis = new SecurityTXTAnalysis();
                        await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger);
                        break;
                    case HealthCheckType.SOA:
                        var soa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.SOA, cancellationToken: cancellationToken);
                        await SOAAnalysis.AnalyzeSoaRecords(soa, _logger);
                        break;
                    case HealthCheckType.OPENRELAY:
                        var mxRecordsForRelay = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> hosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForRelay);
                        foreach (string host in hosts) {
                            cancellationToken.ThrowIfCancellationRequested();
                            await OpenRelayAnalysis.AnalyzeServer(host, 25, _logger, cancellationToken);
                        }
                        break;
                    case HealthCheckType.STARTTLS:
                        var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
                        await StartTlsAnalysis.AnalyzeServers(tlsHosts, new[] { 25 }, _logger, cancellationToken);
                        break;
                    case HealthCheckType.SMTPTLS:
                        var mxRecordsForSmtpTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> smtpTlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForSmtpTls);
                        await SmtpTlsAnalysis.AnalyzeServers(smtpTlsHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.IMAPTLS:
                        var mxRecordsForImapTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> imapTlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForImapTls);
                        await ImapTlsAnalysis.AnalyzeServers(imapTlsHosts, 143, _logger, cancellationToken);
                        break;
                    case HealthCheckType.POP3TLS:
                        var mxRecordsForPop3Tls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> pop3TlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForPop3Tls);
                        await Pop3TlsAnalysis.AnalyzeServers(pop3TlsHosts, 110, _logger, cancellationToken);
                        break;
                    case HealthCheckType.SMTPBANNER:
                        var mxRecordsForBanner = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> bannerHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForBanner);
                        await SmtpBannerAnalysis.AnalyzeServers(bannerHosts, 25, _logger, cancellationToken);
                        break;
                    case HealthCheckType.SMTPAUTH:
                        var mxRecordsForAuth = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
                        IEnumerable<string> authHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForAuth);
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
                    case HealthCheckType.PORTSCAN:
                        await ScanPorts(domainName, null, cancellationToken);
                        break;
                    case HealthCheckType.IPNEIGHBOR:
                        await CheckIPNeighbors(domainName, cancellationToken);
                        break;
                    case HealthCheckType.RPKI:
                        await VerifyRPKI(domainName, cancellationToken);
                        break;
                    case HealthCheckType.DNSTUNNELING:
                        await CheckDnsTunnelingAsync(domainName, cancellationToken);
                        break;
                    case HealthCheckType.TYPOSQUATTING:
                        await VerifyTyposquatting(domainName, cancellationToken);
                        break;
                    case HealthCheckType.WILDCARDDNS:
                        await VerifyWildcardDns(domainName);
                        break;
                    case HealthCheckType.EDNSSUPPORT:
                        EdnsSupportAnalysis = new EdnsSupportAnalysis { DnsConfiguration = DnsConfiguration };
                        await EdnsSupportAnalysis.Analyze(domainName, _logger);
                        break;
                    case HealthCheckType.FLATTENINGSERVICE:
                        FlatteningServiceAnalysis = new FlatteningServiceAnalysis { DnsConfiguration = DnsConfiguration };
                        await FlatteningServiceAnalysis.Analyze(domainName, _logger, cancellationToken);
                        break;
                    case HealthCheckType.THREATINTEL:
                        await VerifyThreatIntel(domainName, cancellationToken);
                        break;
                default:
                    _logger.WriteError("Unknown health check type: {0}", healthCheckType);
                    throw new NotSupportedException("Health check type not implemented.");
                }

                processedChecks++;
                _logger.WriteInformation("{0} check completed", healthCheckType);
                _logger.WriteProgress(
                    "HealthCheck",
                    healthCheckType.ToString(),
                    processedChecks * 100d / totalChecks,
                    processedChecks,
                    totalChecks);
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
        /// Analyzes multiple DANE records.
        /// </summary>
        /// <param name="daneRecords">Collection of TLSA record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDANE(IEnumerable<string> daneRecords, CancellationToken cancellationToken = default) {
            var answers = daneRecords.Select(record => new DnsAnswer {
                DataRaw = record
            }).ToList();
            await DaneAnalysis.AnalyzeDANERecords(answers, _logger);
        }

        /// <summary>
        /// Analyzes a raw SMIMEA record.
        /// </summary>
        /// <param name="smimeaRecord">SMIMEA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSMIMEA(string smimeaRecord, CancellationToken cancellationToken = default) {
            await SmimeaAnalysis.AnalyzeSMIMEARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = smimeaRecord
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
        /// Checks a host for IMAP TLS capabilities.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckImapTlsHost(string host, int port = 143, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await ImapTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for POP3 TLS capabilities.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckPop3TlsHost(string host, int port = 110, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await Pop3TlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
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
        /// Measures mail server connection and banner latency.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckMailLatency(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await MailLatencyAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
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

        /// <summary>
        /// Scans a host for open TCP and UDP ports.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="ports">Ports to scan. Defaults to the top 1000 ports.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task ScanPorts(string host, IEnumerable<int>? ports = null, CancellationToken cancellationToken = default, bool showProgress = true) {
            var list = ports?.ToArray() ?? PortScanAnalysis.DefaultPorts;
            foreach (var p in list) {
                ValidatePort(p);
            }
            await PortScanAnalysis.Scan(host, list, _logger, cancellationToken, showProgress);
        }

        /// <summary>Queries neighbors sharing the same IP as <paramref name="domainName"/>.</summary>
        public async Task CheckIPNeighbors(string domainName, CancellationToken cancellationToken = default) {
            await IPNeighborAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>Analyzes DNS logs for tunneling patterns.</summary>
        public void CheckDnsTunneling(string domainName, CancellationToken ct = default) {
            CheckDnsTunnelingAsync(domainName, ct).GetAwaiter().GetResult();
        }

        public async Task CheckDnsTunnelingAsync(string domainName, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            var lines = DnsTunnelingLogs ?? Array.Empty<string>();
            await Task.Run(() => DnsTunnelingAnalysis.Analyze(domainName, lines), ct);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            TyposquattingAnalysis.DnsConfiguration = DnsConfiguration;
            TyposquattingAnalysis.LevenshteinThreshold = TyposquattingLevenshteinThreshold;
            TyposquattingAnalysis.DetectHomoglyphs = EnableHomoglyphDetection;
            await TyposquattingAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>Queries reputation services for threat listings.</summary>
        /// <param name="domainName">Domain or IP address to check.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyThreatIntel(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            await ThreatIntelAnalysis.Analyze(domainName, GoogleSafeBrowsingApiKey, PhishTankApiKey, VirusTotalApiKey, _logger, cancellationToken);
        }

        /// <summary>
        /// Tests authoritative name servers for EDNS support.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyEdnsSupport(string domainName, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            await EdnsSupportAnalysis.Analyze(domainName, _logger);
        }

        /// <summary>
        /// Validates RPKI origins for domain IPs.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyRPKI(string domainName, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            RpkiAnalysis.DnsConfiguration = DnsConfiguration;
            await RpkiAnalysis.Analyze(domainName, _logger, cancellationToken);
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
        /// Queries random subdomains to detect wildcard DNS behavior.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="sampleCount">Number of names to test.</param>
        public async Task VerifyWildcardDns(string domainName, int sampleCount = 3) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            WildcardDnsAnalysis.DnsConfiguration = DnsConfiguration;
            await WildcardDnsAnalysis.Analyze(domainName, _logger, sampleCount);
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
            return VerifyARCAsync(rawHeaders, ct).GetAwaiter().GetResult();
        }

        public async Task<ARCAnalysis> VerifyARCAsync(string rawHeaders, CancellationToken ct = default) {
            ct.ThrowIfCancellationRequested();
            return await Task.Run(() => {
                ArcAnalysis = new ARCAnalysis();
                ArcAnalysis.Analyze(rawHeaders, _logger);
                return ArcAnalysis;
            }, ct);
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
            domainName = NormalizeDomain(domainName);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            IEnumerable<string> tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            IEnumerable<string> tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            await SmtpTlsAnalysis.AnalyzeServers(tlsHosts, 25, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for IMAP TLS configuration.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyIMAPTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            IEnumerable<string> tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            await ImapTlsAnalysis.AnalyzeServers(tlsHosts, 143, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for POP3 TLS configuration.
        /// </summary>
        /// <param name="domainName">Domain whose MX records are queried.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyPOP3TLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            IEnumerable<string> tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            await Pop3TlsAnalysis.AnalyzeServers(tlsHosts, 110, _logger, cancellationToken);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = CertificateAnalysis.ExtractMxHosts(mx);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = CertificateAnalysis.ExtractMxHosts(mx);
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
            domainName = NormalizeDomain(domainName);
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
            domainName = NormalizeDomain(domainName);
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
            domainName = NormalizeDomain(domainName);
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
            domainName = NormalizeDomain(domainName);
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
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            await NSAnalysis.AnalyzeNsRecords(ns, _logger);
            await NSAnalysis.AnalyzeParentDelegation(domainName, _logger);
        }

        /// <summary>
        /// Detects dangling CNAME records for the domain.
        /// </summary>
        public async Task VerifyDanglingCname(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            DanglingCnameAnalysis = new DanglingCnameAnalysis { DnsConfiguration = DnsConfiguration };
            await DanglingCnameAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// Queries Autodiscover related records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyAutodiscover(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            AutodiscoverAnalysis = new AutodiscoverAnalysis();
            await AutodiscoverAnalysis.Analyze(domainName, DnsConfiguration, _logger, cancellationToken);
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
            var allDaneRecords = new List<DnsAnswer>();
            foreach (var port in ports) {
                cancellationToken.ThrowIfCancellationRequested();
                var query = CreateServiceQuery(port, domainName);
                ValidateServiceQueryProtocol(query);
                var dane = await DnsConfiguration.QueryDNS(query, DnsRecordType.TLSA, cancellationToken: cancellationToken);
                allDaneRecords.AddRange(dane);
            }

            if (allDaneRecords.Count > 0) {
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
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
            var allDaneRecords = new List<DnsAnswer>();

            foreach (var service in services.Distinct()) {
                cancellationToken.ThrowIfCancellationRequested();
                var host = NormalizeDomain(service.Host).TrimEnd('.');
                var daneName = CreateServiceQuery(service.Port, host);
                ValidateServiceQueryProtocol(daneName);
                var dane = await DnsConfiguration.QueryDNS(daneName, DnsRecordType.TLSA, cancellationToken: cancellationToken);
                if (dane.Any()) {
                    allDaneRecords.AddRange(dane);
                }
            }

            if (allDaneRecords.Count > 0) {
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
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
                    var dane = await DnsConfiguration.QueryDNS(daneRecord, DnsRecordType.TLSA, cancellationToken: cancellationToken);
                    if (dane.Any()) {
                        allDaneRecords.AddRange(dane);
                    }
                }

            }
            if (allDaneRecords.Count > 0) {
                await DaneAnalysis.AnalyzeDANERecords(allDaneRecords, _logger);
            } else {
                _logger.WriteWarning("No DANE records found.");
            }
        }

        /// <summary>
        /// Queries SMIMEA records for an email address.
        /// </summary>
        /// <param name="emailAddress">Email address to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySMIMEA(string emailAddress, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(emailAddress)) {
                throw new ArgumentNullException(nameof(emailAddress));
            }

            var name = SMIMEAAnalysis.GetQueryName(emailAddress);
            SmimeaAnalysis = new SMIMEAAnalysis();
            var records = await DnsConfiguration.QueryDNS(name, DnsRecordType.SMIMEA, cancellationToken: cancellationToken);
            if (records.Any()) {
                await SmimeaAnalysis.AnalyzeSMIMEARecords(records, _logger);
            } else {
                _logger.WriteWarning("No SMIMEA records found.");
            }
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
            domainName = ValidateHostName(domainName);
            UpdateIsPublicSuffix(domainName);
            await HttpAnalysis.AnalyzeUrl($"http://{domainName}", false, _logger, cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Sends an ICMP echo request to a host.
        /// </summary>
        /// <param name="host">Target host name or address.</param>
        /// <param name="timeout">Timeout in milliseconds.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task<PingReply> VerifyPing(string host, int timeout = 4000, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            return await PingTraceroute.PingAsync(host, timeout, _logger);
        }

        /// <summary>
        /// Performs a traceroute to the specified host.
        /// </summary>
        /// <param name="host">Target host name or address.</param>
        /// <param name="maxHops">Maximum number of hops to probe.</param>
        /// <param name="timeout">Timeout per hop in milliseconds.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task<IReadOnlyList<PingTraceroute.TracerouteHop>> VerifyTraceroute(string host, int maxHops = 30, int timeout = 4000, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            return await PingTraceroute.TracerouteAsync(host, maxHops, timeout, _logger);
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
        /// Queries WHOIS information and IANA RDAP for a domain.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckWHOIS(string domain, CancellationToken cancellationToken = default) {
            var timeout = WhoisAnalysis.Timeout;
            WhoisAnalysis = new WhoisAnalysis { Timeout = timeout };
            domain = NormalizeDomain(domain);
            UpdateIsPublicSuffix(domain);
            await WhoisAnalysis.QueryWhoisServer(domain, cancellationToken);
            await WhoisAnalysis.QueryIana(domain, cancellationToken);
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

            var hints = new List<string>();

            static void AddHint(List<string> list, HealthCheckType type) {
                var hint = CheckDescriptions.Get(type)?.Remediation;
                if (!string.IsNullOrWhiteSpace(hint)) {
                    list.Add(hint);
                }
            }

            if (!spfValid) {
                AddHint(hints, HealthCheckType.SPF);
            }
            if (!dmarcValid) {
                AddHint(hints, HealthCheckType.DMARC);
            }
            if (!dkimValid) {
                AddHint(hints, HealthCheckType.DKIM);
            }
            if (MXAnalysis is { MxRecordExists: false }) {
                AddHint(hints, HealthCheckType.MX);
            }
            if (!(DnsSecAnalysis?.ChainValid ?? false)) {
                AddHint(hints, HealthCheckType.DNSSEC);
            }
            if (WhoisAnalysis.IsExpired || WhoisAnalysis.ExpiresSoon) {
                hints.Add("Renew the domain registration.");
            }

            return new DomainSummary {
                HasSpfRecord = SpfAnalysis.SpfRecordExists,
                SpfValid = spfValid,
                HasDmarcRecord = DmarcAnalysis.DmarcRecordExists,
                DmarcPolicy = DmarcAnalysis.Policy,
                DmarcValid = dmarcValid,
                HasDkimRecord = DKIMAnalysis.AnalysisResults.Values.Any(a => a.DkimRecordExists),
                DkimValid = dkimValid,
                HasMxRecord = MXAnalysis?.MxRecordExists ?? false,
                DnsSecValid = DnsSecAnalysis?.ChainValid ?? false,
                IsPublicSuffix = IsPublicSuffix,
                ExpiryDate = WhoisAnalysis.ExpiryDate,
                ExpiresSoon = WhoisAnalysis.ExpiresSoon,
                IsExpired = WhoisAnalysis.IsExpired,
                RegistrarLocked = WhoisAnalysis.RegistrarLocked,
                PrivacyProtected = WhoisAnalysis.PrivacyProtected,
                Hints = hints.ToArray()
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
            options ??= JsonOptions;
            if (UnicodeOutput && options.Converters.All(c => c is not IdnStringConverter)) {
                var local = new JsonSerializerOptions(options);
                local.Converters.Add(new IdnStringConverter(true));
                return JsonSerializer.Serialize(this, local);
            }
            return JsonSerializer.Serialize(this, options);
        }

        private static void ValidatePort(int port) {
            if (port <= 0 || port > 65535) {
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");
            }
        }

        private static string ValidateHostName(string domainName) {
            var trimmed = domainName?.Trim();
            if (string.IsNullOrWhiteSpace(trimmed)) {
                throw new ArgumentNullException(nameof(domainName));
            }

            if (!Uri.TryCreate($"http://{trimmed}", UriKind.Absolute, out var uri)) {
                // older frameworks may not handle IDN automatically
                var host = trimmed;
                var portIndex = trimmed.LastIndexOf(':');
                if (portIndex > 0 && trimmed.IndexOf(':') == portIndex &&
                    int.TryParse(trimmed.Substring(portIndex + 1), out _)) {
                    host = trimmed.Substring(0, portIndex);
                }

                try {
                    host = _idn.GetAscii(host.Trim().Trim('.'));
                } catch (ArgumentException) {
                    throw new ArgumentException("Invalid host name.", nameof(domainName));
                }

                var rebuilt = portIndex > 0 && trimmed.IndexOf(':') == portIndex
                    ? host + trimmed.Substring(portIndex)
                    : host;

                if (!Uri.TryCreate($"http://{rebuilt}", UriKind.Absolute, out uri)) {
                    throw new ArgumentException("Invalid host name.", nameof(domainName));
                }
            }

            if (!string.IsNullOrEmpty(uri.PathAndQuery) && uri.PathAndQuery != "/" ||
                !string.IsNullOrEmpty(uri.Fragment)) {
                throw new ArgumentException("Invalid host name.", nameof(domainName));
            }

            if (!uri.IsDefaultPort) {
                if (uri.Port <= 0 || uri.Port > 65535) {
                    throw new ArgumentException("Invalid port.", nameof(domainName));
                }
                return $"{NormalizeDomain(uri.IdnHost)}:{uri.Port}";
            }

            return NormalizeDomain(uri.IdnHost);
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
            filtered.FcrDnsAnalysis = active.Contains(HealthCheckType.FCRDNS) ? CloneAnalysis(FcrDnsAnalysis) : null;
            filtered.CAAAnalysis = active.Contains(HealthCheckType.CAA) ? CloneAnalysis(CAAAnalysis) : null;
            filtered.NSAnalysis =
                active.Contains(HealthCheckType.NS) || active.Contains(HealthCheckType.DELEGATION)
                    ? CloneAnalysis(NSAnalysis)
                    : null;
            filtered.ZoneTransferAnalysis = active.Contains(HealthCheckType.ZONETRANSFER) ? CloneAnalysis(ZoneTransferAnalysis) : null;
            filtered.DaneAnalysis = active.Contains(HealthCheckType.DANE) ? CloneAnalysis(DaneAnalysis) : null;
            filtered.DNSBLAnalysis = active.Contains(HealthCheckType.DNSBL) ? CloneAnalysis(DNSBLAnalysis) : null;
            filtered.DnsSecAnalysis = active.Contains(HealthCheckType.DNSSEC) ? CloneAnalysis(DnsSecAnalysis) : null;
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
            filtered.ImapTlsAnalysis = active.Contains(HealthCheckType.IMAPTLS) ? CloneAnalysis(ImapTlsAnalysis) : null;
            filtered.Pop3TlsAnalysis = active.Contains(HealthCheckType.POP3TLS) ? CloneAnalysis(Pop3TlsAnalysis) : null;
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
            filtered.PortScanAnalysis = active.Contains(HealthCheckType.PORTSCAN) ? CloneAnalysis(PortScanAnalysis) : null;
            filtered.IPNeighborAnalysis = active.Contains(HealthCheckType.IPNEIGHBOR) ? CloneAnalysis(IPNeighborAnalysis) : null;
            filtered.DnsTunnelingAnalysis = active.Contains(HealthCheckType.DNSTUNNELING) ? CloneAnalysis(DnsTunnelingAnalysis) : null;
            filtered.TyposquattingAnalysis = active.Contains(HealthCheckType.TYPOSQUATTING) ? CloneAnalysis(TyposquattingAnalysis) : null;
            filtered.ThreatIntelAnalysis = active.Contains(HealthCheckType.THREATINTEL) ? CloneAnalysis(ThreatIntelAnalysis) : null;
            filtered.WildcardDnsAnalysis = active.Contains(HealthCheckType.WILDCARDDNS) ? CloneAnalysis(WildcardDnsAnalysis) : null;
            filtered.EdnsSupportAnalysis = active.Contains(HealthCheckType.EDNSSUPPORT) ? CloneAnalysis(EdnsSupportAnalysis) : null;
            filtered.FlatteningServiceAnalysis = active.Contains(HealthCheckType.FLATTENINGSERVICE) ? CloneAnalysis(FlatteningServiceAnalysis) : null;

            return filtered;
        }

        private static readonly MethodInfo _cloneMethod = typeof(object).GetMethod(
            "MemberwiseClone",
            BindingFlags.Instance | BindingFlags.NonPublic);

        private static class Cloner<T> where T : class {
            internal static readonly Func<T, T> Delegate = CreateDelegate();

            private static Func<T, T> CreateDelegate() {
                ParameterExpression param = Expression.Parameter(typeof(T), "source");
                UnaryExpression body = Expression.Convert(Expression.Call(param, _cloneMethod), typeof(T));
                return Expression.Lambda<Func<T, T>>(body, param).Compile();
            }
        }

        private static T CloneAnalysis<T>(T analysis) where T : class {
            return analysis == null ? null : Cloner<T>.Delegate(analysis);
        }
    }
}
