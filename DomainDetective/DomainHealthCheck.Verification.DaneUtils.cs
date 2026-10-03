using DnsClientX;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private Task VerifyDaneAsync(string domainName, ServiceType[]? serviceTypes, int[]? ports, CancellationToken cancellationToken)
            => EnsureDaneAsync(domainName, serviceTypes, ports, cancellationToken);

        private async Task VerifyDaneInternal(string domainName, ServiceType[]? serviceTypes, int[]? ports, CancellationToken cancellationToken) {
            if (ports != null && ports.Length > 0) {
                await VerifyDANE(domainName, ports, cancellationToken);
            } else {
                await VerifyDANE(domainName, serviceTypes ?? System.Array.Empty<ServiceType>(), cancellationToken);
            }
        }

        private async Task<DnsAnswer[]> QueryDaneDns(string name, CancellationToken cancellationToken) {
            if (DaneAnalysis.QueryDnsOverride != null) {
                return DANEAnalysis.BindServiceTlsaAnswers(name,
                    await DaneAnalysis.QueryDnsOverride(name, DnsRecordType.TLSA));
            }

            var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { name }, DnsRecordType.TLSA,
                cancellationToken: cancellationToken);
            return DANEAnalysis.BindServiceTlsaAnswers(name, responses[0]);
        }
    }
}
