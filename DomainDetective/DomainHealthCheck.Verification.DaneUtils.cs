using DnsClientX;
using System;
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
            try {
                if (DaneAnalysis.QueryDnsOverride != null) {
                    return DANEAnalysis.BindServiceTlsaAnswers(name,
                        await DaneAnalysis.QueryDnsOverride(name, DnsRecordType.TLSA));
                }

                var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { name }, DnsRecordType.TLSA,
                    cancellationToken: cancellationToken);
                DnsResponse? response = responses[0];
                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                    DaneAnalysis.RecordDnsQueryFailure(name, DescribeDaneDnsFailure(response), _logger);
                    return Array.Empty<DnsAnswer>();
                }
                return DANEAnalysis.BindServiceTlsaAnswers(name, response);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception exception) when (exception is TimeoutException ||
                exception is TaskCanceledException || exception is System.Net.Http.HttpRequestException) {
                DaneAnalysis.RecordDnsQueryFailure(name, exception.Message, _logger);
                return Array.Empty<DnsAnswer>();
            }
        }

        private async Task<DnsAnswer[]> QueryDaneMxDns(string domainName, CancellationToken cancellationToken) {
            try {
                var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { domainName }, DnsRecordType.MX,
                    cancellationToken: cancellationToken);
                DnsResponse? response = responses[0];
                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                    DaneAnalysis.RecordDnsQueryFailure(domainName, DescribeDaneDnsFailure(response), _logger);
                    return Array.Empty<DnsAnswer>();
                }
                return response.Answers ?? Array.Empty<DnsAnswer>();
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception exception) when (exception is TimeoutException ||
                exception is TaskCanceledException || exception is System.Net.Http.HttpRequestException) {
                DaneAnalysis.RecordDnsQueryFailure(domainName, exception.Message, _logger);
                return Array.Empty<DnsAnswer>();
            }
        }

        private static string DescribeDaneDnsFailure(DnsResponse? response) {
            string? error = response?.Error;
            if (error != null && error.Length > 0) return error;
            return response == null ? "no resolver response" : response.Status.ToString();
        }
    }
}
