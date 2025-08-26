using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Analyzes apex A/AAAA records for a domain and surfaces whether
    /// address records exist that SMTP could use as a fallback when
    /// MX records are absent (RFC 5321).
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class ApexAddressAnalysis {
        /// <summary>DNS configuration used for lookups when needed.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Optional DNS query override for testing.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Apex A records discovered.</summary>
        public List<string> ARecords { get; private set; } = new();
        /// <summary>Apex AAAA records discovered.</summary>
        public List<string> AaaaRecords { get; private set; } = new();
        /// <summary>True when at least one A record exists.</summary>
        public bool HasARecord { get; private set; }
        /// <summary>True when at least one AAAA record exists.</summary>
        public bool HasAaaaRecord { get; private set; }
        /// <summary>True when either A or AAAA records exist.</summary>
        public bool HasAnyAddress => HasARecord || HasAaaaRecord;

        /// <summary>Relevant standards for apex address (SMTP fallback) behavior.</summary>
        public IReadOnlyList<StandardReference> RfcReferences => new[] {
            new StandardReference { Title = "Simple Mail Transfer Protocol", Reference = "RFC 5321", Url = "https://datatracker.ietf.org/doc/html/rfc5321" }
        };

        public void Reset() {
            ARecords = new List<string>();
            AaaaRecords = new List<string>();
            HasARecord = false;
            HasAaaaRecord = false;
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }
            return await DnsConfiguration.QueryDNS(name, type);
        }

        /// <summary>
        /// Analyzes apex address answers supplied by the caller.
        /// </summary>
        public Task AnalyzeApexAnswers(IEnumerable<DnsAnswer> aAnswers, IEnumerable<DnsAnswer> aaaaAnswers, InternalLogger? logger = null) {
            Reset();
            if (aAnswers != null) {
                foreach (var a in aAnswers) {
                    if (!string.IsNullOrWhiteSpace(a.Data)) {
                        ARecords.Add(a.Data);
                    }
                }
            }
            if (aaaaAnswers != null) {
                foreach (var a in aaaaAnswers) {
                    if (!string.IsNullOrWhiteSpace(a.Data)) {
                        AaaaRecords.Add(a.Data);
                    }
                }
            }

            HasARecord = ARecords.Count > 0;
            HasAaaaRecord = AaaaRecords.Count > 0;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Queries and analyzes apex A/AAAA for the given domain using configured DNS.
        /// </summary>
        public async Task AnalyzeAsync(string domainName, InternalLogger? logger = null) {
            Reset();
            var a = await QueryDns(domainName, DnsRecordType.A) ?? Array.Empty<DnsAnswer>();
            var aaaa = await QueryDns(domainName, DnsRecordType.AAAA) ?? Array.Empty<DnsAnswer>();
            await AnalyzeApexAnswers(a, aaaa, logger);
        }
    }
}

