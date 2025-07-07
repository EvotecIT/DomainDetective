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

        /// <summary>Optional override for the MTA-STS policy URL.</summary>
        /// <value>A URL to use instead of querying DNS.</value>
        public string MtaStsPolicyUrlOverride { get; set; }

        /// <summary>API key for Google Safe Browsing.</summary>
        public string? GoogleSafeBrowsingApiKey { get; set; }

        /// <summary>API key for PhishTank.</summary>
        public string? PhishTankApiKey { get; set; }

        /// <summary>API key for VirusTotal.</summary>
        public string? VirusTotalApiKey { get; set; }

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
                return _cacheDirectory;
            }
            set => _cacheDirectory = value;
        }

        private string? _cacheDirectory;
      
        /// <summary>Maximum Levenshtein distance used for typosquatting detection.</summary>
        public int TyposquattingLevenshteinThreshold { get; set; } = 1;

        /// <summary>Enable detection of homoglyph characters.</summary>
        public bool EnableHomoglyphDetection { get; set; } = true;
    }
}
