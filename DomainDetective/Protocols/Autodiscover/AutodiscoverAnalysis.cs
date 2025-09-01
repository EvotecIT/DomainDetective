using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes Autodiscover related DNS records.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Results indicate whether common autodiscover records are present and
    /// where they point, assisting in troubleshooting client configuration.
    /// </remarks>
    public class AutodiscoverAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        /// <summary>DNS configuration used for lookups.</summary>
        public DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>Optional DNS query override.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        private readonly List<AutodiscoverEndpointResult> _endpoints = new();
        /// <summary>Results of endpoint checks in the order attempted.</summary>
        public IReadOnlyList<AutodiscoverEndpointResult> Endpoints => _endpoints;
        /// <summary>Populate endpoint results discovered by HTTP analysis.</summary>
        public void SetHttpEndpoints(IReadOnlyList<AutodiscoverEndpointResult>? endpoints)
        {
            _endpoints.Clear();
            if (endpoints == null) return;
            foreach (var e in endpoints) if (e != null) _endpoints.Add(e);
        }
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

        public List<Assessment> Assessments { get; } = new();

        public async Task Analyze(string domainName, DnsConfiguration config, InternalLogger logger, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }

            Subject = domainName;

            var srv = await QueryDns($"_autodiscover._tcp.{domainName}", DnsRecordType.SRV, config);
            SrvRecordExists = srv != null && srv.Any();
            if (SrvRecordExists) {
                var parts = srv.First().Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4 && int.TryParse(parts[2], out var port)) {
                    SrvPort = port;
                    SrvTarget = parts[3].TrimEnd('.');
                }
                if (string.IsNullOrWhiteSpace(SrvTarget)) {
                    using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: domainName);
                    logger?.WriteWarningCode(AutodiscoverCodes.BadSrvTarget, "_autodiscover._tcp SRV target missing or invalid");
                }
            } else {
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: domainName);
                logger?.WriteWarningCode(AutodiscoverCodes.MissingSrv, "_autodiscover._tcp SRV record missing");
            }

            var ac = await QueryDns($"autoconfig.{domainName}", DnsRecordType.CNAME, config);
            AutoconfigCnameExists = ac != null && ac.Any();
            if (AutoconfigCnameExists) {
                AutoconfigTarget = ac.First().Data.TrimEnd('.');
                if (string.IsNullOrWhiteSpace(AutoconfigTarget)) {
                    using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: $"autoconfig.{domainName}");
                    logger?.WriteWarningCode(AutodiscoverCodes.BadAutoconfigTarget, "Autoconfig CNAME target invalid");
                }
            } else {
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: $"autoconfig.{domainName}");
                logger?.WriteWarningCode(AutodiscoverCodes.MissingAutoconfigCname, "Autoconfig CNAME missing");
            }

            var ad = await QueryDns($"autodiscover.{domainName}", DnsRecordType.CNAME, config);
            AutodiscoverCnameExists = ad != null && ad.Any();
            if (AutodiscoverCnameExists) {
                AutodiscoverTarget = ad.First().Data.TrimEnd('.');
                if (string.IsNullOrWhiteSpace(AutodiscoverTarget)) {
                    using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: $"autodiscover.{domainName}");
                    logger?.WriteWarningCode(AutodiscoverCodes.BadAutodiscoverTarget, "Autodiscover CNAME target invalid");
                }
            } else {
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "Autodiscover", target: $"autodiscover.{domainName}");
                logger?.WriteWarningCode(AutodiscoverCodes.MissingAutodiscoverCname, "Autodiscover CNAME missing");
            }
        }
    }
}
