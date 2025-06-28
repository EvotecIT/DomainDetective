using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes Autodiscover related DNS records.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class AutodiscoverAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        /// <summary>Gets a value indicating whether the _autodiscover._tcp SRV record exists.</summary>
        public bool SrvRecordExists { get; private set; }
        /// <summary>Gets the SRV target host if present.</summary>
        public string? SrvTarget { get; private set; }
        /// <summary>Gets the SRV port if present.</summary>
        public int SrvPort { get; private set; }
        /// <summary>Gets a value indicating whether autoconfig CNAME exists.</summary>
        public bool AutoconfigCnameExists { get; private set; }
        /// <summary>Gets the autoconfig CNAME target.</summary>
        public string? AutoconfigTarget { get; private set; }
        /// <summary>Gets a value indicating whether autodiscover CNAME exists.</summary>
        public bool AutodiscoverCnameExists { get; private set; }
        /// <summary>Gets the autodiscover CNAME target.</summary>
        public string? AutodiscoverTarget { get; private set; }

        /// <summary>
        /// Queries DNS for Autodiscover related records.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, DnsConfiguration config) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            return await config.QueryDNS(name, type);
        }

        public async Task Analyze(string domainName, DnsConfiguration config, InternalLogger logger, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }

            var srv = await QueryDns($"_autodiscover._tcp.{domainName}", DnsRecordType.SRV, config);
            SrvRecordExists = srv != null && srv.Any();
            if (SrvRecordExists) {
                var parts = srv.First().Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4 && int.TryParse(parts[2], out var port)) {
                    SrvPort = port;
                    SrvTarget = parts[3].TrimEnd('.');
                }
            }

            var ac = await QueryDns($"autoconfig.{domainName}", DnsRecordType.CNAME, config);
            AutoconfigCnameExists = ac != null && ac.Any();
            if (AutoconfigCnameExists) {
                AutoconfigTarget = ac.First().Data.TrimEnd('.');
            }

            var ad = await QueryDns($"autodiscover.{domainName}", DnsRecordType.CNAME, config);
            AutodiscoverCnameExists = ad != null && ad.Any();
            if (AutodiscoverCnameExists) {
                AutodiscoverTarget = ad.First().Data.TrimEnd('.');
            }
        }
    }
}
