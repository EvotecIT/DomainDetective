using DnsClientX;
using System;
using System.Collections.Generic;
using System.IO;

namespace DomainDetective {
    /// <summary>
    /// Provides configuration options and tunables for domain health checks.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class DomainHealthCheck {
        /// <summary>
        /// When true, DMARC policy strength evaluation checks the <c>sp</c> tag.
        /// </summary>
        public bool UseSubdomainPolicy { get; set; }

        /// <summary>Display domain names in Unicode where possible.</summary>
        public bool UnicodeOutput { get; set; }

        /// <summary>DNS server used when querying records.</summary>
        /// <value>The endpoint for DNS queries.</value>
        public DnsEndpoint DnsEndpoint {
            get => DnsConfiguration.DnsEndpoint;
            set {
                _logger.WriteVerbose("Setting DnsEndpoint to {0}", value);
                DnsConfiguration.DnsEndpoint = value;
            }
        }

        /// <summary>Strategy for choosing the DNS server when multiple are configured.</summary>
        /// <value>The selection strategy.</value>
        public DnsSelectionStrategy DnsSelectionStrategy {
            get => DnsConfiguration.DnsSelectionStrategy;
            set {
                _logger.WriteVerbose("Setting DnsSelectionStrategy to {0}", value);
                DnsConfiguration.DnsSelectionStrategy = value;
            }
        }

        /// <summary>Optional list of resolver endpoints to use (multi-resolver).</summary>
        public List<DnsEndpoint> DnsEndpoints => DnsConfiguration.DnsEndpoints;

        /// <summary>Strategy for multi-resolver queries.</summary>
        public MultiResolverStrategy MultiResolverStrategy {
            get => DnsConfiguration.MultiResolverStrategy;
            set {
                _logger.WriteVerbose("Setting MultiResolverStrategy to {0}", value);
                DnsConfiguration.MultiResolverStrategy = value;
            }
        }

        /// <summary>Maximum number of resolvers to query in parallel (null means all).</summary>
        public int? MultiResolverMaxParallelism {
            get => DnsConfiguration.MultiResolverMaxParallelism;
            set {
                _logger.WriteVerbose("Setting MultiResolverMaxParallelism to {0}", value);
                DnsConfiguration.MultiResolverMaxParallelism = value;
            }
        }

        /// <summary>Optional concurrency hint for DNS resolver queries.</summary>
        public int? ResolverMaxConcurrency {
            get => DnsConfiguration.ResolverMaxConcurrency;
            set {
                _logger.WriteVerbose("Setting ResolverMaxConcurrency to {0}", value);
                DnsConfiguration.ResolverMaxConcurrency = value;
            }
        }

        /// <summary>Execution options for running health checks.</summary>
        public HealthCheckExecutionOptions ExecutionOptions { get; } = new HealthCheckExecutionOptions();

        /// <summary>Optional override for the MTA-STS policy URL.</summary>
        /// <value>A URL to use instead of querying DNS.</value>
        public string? MtaStsPolicyUrlOverride {
            get => _mtaStsPolicyUrlOverride;
            set {
                if (value is null) {
                    _mtaStsPolicyUrlOverride = null;
                } else if (!Uri.TryCreate(value, UriKind.Absolute, out _)) {
                    throw new ArgumentException("Value must be an absolute URI", nameof(value));
                } else {
                    _mtaStsPolicyUrlOverride = value;
                }
            }
        }

        private string? _mtaStsPolicyUrlOverride;

        /// <summary>API key for Google Safe Browsing.</summary>
        public string? GoogleSafeBrowsingApiKey { get; set; }

        /// <summary>API key for PhishTank.</summary>
        public string? PhishTankApiKey { get; set; }

        /// <summary>API key for VirusTotal.</summary>
        public string? VirusTotalApiKey { get; set; }

        /// <summary>API key for AbuseIPDB.</summary>
        public string? AbuseIpDbApiKey { get; set; }

        /// <summary>Log lines used for DNS tunneling analysis.</summary>
        public IEnumerable<string>? DnsTunnelingLogs { get; set; }

        private DnsConfiguration _dnsConfiguration = new DnsConfiguration();

        /// <summary>Holds DNS client configuration used throughout analyses.</summary>
        /// <value>The DNS configuration instance. The health check owns and disposes the assigned configuration.</value>
        public DnsConfiguration DnsConfiguration {
            get => _dnsConfiguration;
            set {
                if (value == null) throw new ArgumentNullException(nameof(value));
                if (ReferenceEquals(_dnsConfiguration, value)) return;
                DnsConfiguration previous = _dnsConfiguration;
                _dnsConfiguration = value;
                ApplyDnsConfiguration(value);
                previous.Dispose();
            }
        }

        private void ApplyDnsConfiguration(DnsConfiguration configuration) {
            DmarcAnalysis.DnsConfiguration = configuration;
            WhoisAnalysis.DnsConfiguration = configuration;
            SpfAnalysis.DnsConfiguration = configuration;
            MXAnalysis.DnsConfiguration = configuration;
            ReverseDnsAnalysis.DnsConfiguration = configuration;
            FcrDnsAnalysis.DnsConfiguration = configuration;
            NSAnalysis.DnsConfiguration = configuration;
            DNSBLAnalysis.DnsConfiguration = configuration;
            MTASTSAnalysis.DnsConfiguration = configuration;
            DanglingCnameAnalysis.DnsConfiguration = configuration;
            SubdomainsAnalysis.DnsConfiguration = configuration;
            DnsInventoryAnalysis.DnsConfiguration = configuration;
            DnsTraceAnalysis.DnsConfiguration = configuration;
            IpEnrichmentAnalysis.DnsConfiguration = configuration;
            DnsTtlAnalysis.DnsConfiguration = configuration;
            DKIMAnalysis.DnsConfiguration = configuration;
            IPNeighborAnalysis.DnsConfiguration = configuration;
            RpkiAnalysis.DnsConfiguration = configuration;
            TyposquattingAnalysis.DnsConfiguration = configuration;
            WildcardDnsAnalysis.DnsConfiguration = configuration;
            EdnsSupportAnalysis.DnsConfiguration = configuration;
            DnsAmplificationAnalysis.DnsConfiguration = configuration;
            DnsOverTlsAnalysis.DnsConfiguration = configuration;
            FlatteningServiceAnalysis.DnsConfiguration = configuration;
            TakeoverCnameAnalysis.DnsConfiguration = configuration;
            AutodiscoverAnalysis.DnsConfiguration = configuration;
            WebStaticScanAnalysis.DnsConfiguration = configuration;
            ApexAddressAnalysis.DnsConfiguration = configuration;
            DnsHealthAnalysis.DnsConfiguration = configuration;
            EmailAddressValidationAnalysis.DnsConfiguration = configuration;
        }

        /// <summary>
        /// Directory used for caching downloaded data.
        /// </summary>
        public string CacheDirectory {
            get {
                if (_cacheDirectory is null) {
                    var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    _cacheDirectory = Path.Combine(home, ".domain-detective");
                }
                if (!string.IsNullOrEmpty(_cacheDirectory) && !Directory.Exists(_cacheDirectory)) {
                    Directory.CreateDirectory(_cacheDirectory);
                }
                return _cacheDirectory;
            }
            set {
                _cacheDirectory = value;
                if (!string.IsNullOrEmpty(_cacheDirectory) && !Directory.Exists(_cacheDirectory)) {
                    Directory.CreateDirectory(_cacheDirectory);
                }
            }
        }

        private string? _cacheDirectory;
      
        /// <summary>Maximum Levenshtein distance used for typosquatting detection.</summary>
        public int TyposquattingLevenshteinThreshold { get; set; } = 1;

        /// <summary>Enable detection of homoglyph characters.</summary>
        public bool EnableHomoglyphDetection { get; set; } = true;

        /// <summary>Protected brand keywords for typosquatting detection.</summary>
        public List<string> TyposquattingBrandKeywords { get; } = new();

        /// <summary>When true, promising typosquatting candidates are enriched with additional DD analyses.</summary>
        public bool TyposquattingEnableEnrichment { get; set; } = true;

        /// <summary>Maximum number of typosquatting candidates enriched after DNS screening.</summary>
        public int TyposquattingEnrichmentMaxCandidates { get; set; } = 10;

        /// <summary>Maximum number of typosquatting enrichments performed in parallel.</summary>
        public int TyposquattingEnrichmentMaxParallelism { get; set; } = 2;

        /// <summary>When true, typosquatting enrichment includes WHOIS.</summary>
        public bool TyposquattingEnrichWhois { get; set; } = true;

        /// <summary>When true, typosquatting enrichment includes HTTP posture.</summary>
        public bool TyposquattingEnrichHttp { get; set; } = true;

        /// <summary>When true, typosquatting enrichment includes IP enrichment.</summary>
        public bool TyposquattingEnrichIp { get; set; } = true;

        /// <summary>When true, typosquatting enrichment includes SMTP banner checks on candidate MX hosts.</summary>
        public bool TyposquattingEnrichSmtpBanner { get; set; }

        /// <summary>When true, typosquatting enrichment checks whether candidate MX hosts accept mail for the lookalike domain.</summary>
        public bool TyposquattingEnrichSmtpRecipientAcceptance { get; set; }

        /// <summary>When true, typosquatting enrichment includes static web discovery.</summary>
        public bool TyposquattingEnrichWebStaticScan { get; set; }

        /// <summary>When true, typosquatting enrichment includes threat intelligence lookups.</summary>
        public bool TyposquattingEnrichThreatIntel { get; set; }

        /// <summary>When true, typosquatting HTTP enrichment captures response bodies.</summary>
        public bool TyposquattingCaptureHttpBody { get; set; }

        /// <summary>When true, typosquatting candidates are compared with the source domain ownership footprint.</summary>
        public bool TyposquattingCompareOwnershipSignals { get; set; }

        /// <summary>When true, the source-domain ownership profile includes WHOIS registrar data.</summary>
        public bool TyposquattingOwnershipIncludeWhois { get; set; } = true;

        /// <summary>When true, the source-domain ownership profile includes IP enrichment and ASN data.</summary>
        public bool TyposquattingOwnershipIncludeIp { get; set; } = true;

        /// <summary>When true, the source-domain ownership profile includes MX host overlap checks.</summary>
        public bool TyposquattingOwnershipIncludeMx { get; set; } = true;

        /// <summary>When true, typosquatting candidates are compared with the source domain web content.</summary>
        public bool TyposquattingEnableContentSimilarity { get; set; } = true;

        /// <summary>When true, content similarity also uses static web analysis for title and technology overlap.</summary>
        public bool TyposquattingSimilarityIncludeWebStaticScan { get; set; }

        /// <summary>When true, typosquatting candidates are compared using reusable visual fingerprints.</summary>
        public bool TyposquattingEnableVisualSimilarity { get; set; }

        /// <summary>Maximum number of typosquatting candidates included in visual comparison.</summary>
        public int TyposquattingVisualMaxCandidates { get; set; } = 5;

        /// <summary>Maximum number of parallel visual comparisons.</summary>
        public int TyposquattingVisualMaxParallelism { get; set; } = 2;

        /// <summary>When true, visual similarity can fall back to static asset discovery such as favicons and OG images.</summary>
        public bool TyposquattingVisualUseStaticAssetCapture { get; set; } = true;

        /// <summary>When true, visual similarity can try a built-in rendered browser screenshot provider.</summary>
        public bool TyposquattingVisualUseBrowserCapture { get; set; }

        /// <summary>Maximum number of bytes downloaded for a single typosquatting visual asset.</summary>
        public int TyposquattingVisualMaxAssetBytes { get; set; } = 1024 * 1024;

        /// <summary>Maximum number of visual assets compared per source or candidate page.</summary>
        public int TyposquattingVisualMaxAssetsPerPage { get; set; } = 3;

        /// <summary>
        /// When true, DNSSEC posture is derived from DnsClientX local validation rather than a resolver AD claim.
        /// </summary>
        public bool DnsSecValidateLocally { get; set; } = true;

        /// <summary>Record types tested for DNS propagation (multi-resolver) checks.</summary>
        public DnsRecordType[] DnsPropagationRecordTypes { get; set; } = new[] { DnsRecordType.A, DnsRecordType.AAAA };

        /// <summary>Maximum number of public resolvers queried for DNS propagation (bounded for responsiveness).</summary>
        public int DnsPropagationMaxServers { get; set; } = 60;

        /// <summary>Maximum parallel DNS propagation queries.</summary>
        public int DnsPropagationMaxParallelism { get; set; } = 20;

        /// <summary>When true, includes GeoIP lookups for mappable country rollups.</summary>
        public bool DnsPropagationIncludeGeo { get; set; } = true;

        /// <summary>Maximum number of resolver results retained per record type for reporting.</summary>
        public int DnsPropagationMaxResultsToKeep { get; set; } = 500;
    }
}
