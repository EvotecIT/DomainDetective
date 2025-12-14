using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private async Task VerifyDaneAsync(string domainName, ServiceType[]? serviceTypes, int[]? ports, CancellationToken cancellationToken) {
            if (ports != null && ports.Length > 0) {
                await VerifyDANE(domainName, ports, cancellationToken);
            } else {
                await VerifyDANE(domainName, serviceTypes ?? System.Array.Empty<ServiceType>(), cancellationToken);
            }
        }

        private async Task<DnsAnswer[]> QueryDaneDns(string name, CancellationToken cancellationToken) {
            if (DaneAnalysis.QueryDnsOverride != null) {
                return await DaneAnalysis.QueryDnsOverride(name, DnsRecordType.TLSA);
            }

            return await DnsConfiguration.QueryDNS(name, DnsRecordType.TLSA, cancellationToken: cancellationToken);
        }
    }
}
