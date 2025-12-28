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

        /// <summary>Holds DNS client configuration used throughout analyses.</summary>
        /// <value>The DNS configuration instance.</value>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

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

        /// <summary>
        /// When true, DNSSEC queries use local validation (validateDnsSec: true) in DnsClientX.
        /// </summary>
        public bool DnsSecValidateLocally { get; set; }
    }
}
