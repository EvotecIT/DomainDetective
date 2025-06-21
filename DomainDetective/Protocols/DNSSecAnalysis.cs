using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    public class DNSSecAnalysis {
        public IReadOnlyList<DnsAnswer> DnsKeys { get; private set; } = new List<DnsAnswer>();
        public IReadOnlyList<DnsAnswer> Signatures { get; private set; } = new List<DnsAnswer>();
        public bool AuthenticData { get; private set; }

        public async Task Analyze(string domainName, InternalLogger logger, DnsConfiguration dnsConfiguration = null) {
            var endpoint = dnsConfiguration?.DnsEndpoint ?? DnsEndpoint.Cloudflare;
            var strategy = dnsConfiguration?.DnsSelectionStrategy ?? DnsSelectionStrategy.First;

            var client = new ClientX(endpoint: endpoint, strategy, timeOutMilliseconds: 0);

            var responses = await client.Resolve(domainName, [DnsRecordType.DNSKEY, DnsRecordType.RRSIG], requestDnsSec: true, validateDnsSec: true);

            var records = responses.SelectMany(r => r.Answers).ToList();
            DnsKeys = records.Where(a => a.Type == DnsRecordType.DNSKEY).ToList();
            Signatures = records.Where(a => a.Type == DnsRecordType.RRSIG).ToList();

            AuthenticData = responses.All(r => r.AuthenticData);

            logger?.WriteVerbose("DNSSEC validation for {0}: {1}", domainName, AuthenticData);
        }
    }
}