using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private const int MaxDaneHostAliasHops = 8;

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

        private async Task<DnsAnswer[]> QueryDaneServiceAsync(string host, int port,
            Dictionary<string, string?> secureAliases, CancellationToken cancellationToken) {
            host = NormalizeDomain(host).TrimEnd('.');
            if (!secureAliases.TryGetValue(host, out string? target)) {
                target = await ResolveSecureDaneHostAliasAsync(host, cancellationToken);
                secureAliases.Add(host, target);
            }

            if (target != null) {
                string targetOwner = CreateServiceQuery(port, target);
                RecordDaneQueryName(targetOwner);
                DnsAnswer[] targetRecords = await QueryDaneDns(targetOwner, cancellationToken);
                if (targetRecords.Length > 0) {
                    return targetRecords;
                }
            }

            string originalOwner = CreateServiceQuery(port, host);
            RecordDaneQueryName(originalOwner);
            return await QueryDaneDns(originalOwner, cancellationToken);
        }

        private void RecordDaneQueryName(string name) {
            if (!DaneAnalysis.QueriedNames.Contains(name, StringComparer.OrdinalIgnoreCase)) {
                DaneAnalysis.QueriedNames.Add(name);
            }
        }

        private async Task<string?> ResolveSecureDaneHostAliasAsync(string host, CancellationToken cancellationToken) {
            // Answer-only overrides cannot establish that a CNAME hop is DNSSEC Secure.
            if (DnsConfiguration.QueryDnsResponseOverride == null &&
                (DaneDnsOverride != null || DnsConfiguration.QueryDnsOverride != null)) {
                return null;
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { host };
            string current = host;
            for (int hop = 0; hop <= MaxDaneHostAliasHops; hop++) {
                cancellationToken.ThrowIfCancellationRequested();
                DnsResponse response;
                try {
                    response = await DnsSecAnalysis.QueryValidatedSubjectResponseAsync(
                        current, DnsRecordType.CNAME, DnsConfiguration, cancellationToken);
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                } catch (Exception exception) when (exception is TimeoutException || exception is TaskCanceledException ||
                    exception is HttpRequestException || exception is SocketException) {
                    DaneAnalysis.RecordDnsQueryFailure(current, exception.Message, _logger);
                    return null;
                }

                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError ||
                    response.DnsSecValidationStatus != DnsSecValidationStatus.Secure) {
                    return null;
                }

                DnsAnswer[] cnames = (response.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == DnsRecordType.CNAME &&
                        string.Equals(answer.Name?.TrimEnd('.'), current, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (cnames.Length == 0) {
                    return hop == 0 ? null : current;
                }
                if (cnames.Length != 1 || hop == MaxDaneHostAliasHops) {
                    return null;
                }

                string target;
                try {
                    target = NormalizeDomain(cnames[0].Data ?? cnames[0].DataRaw).TrimEnd('.');
                } catch (ArgumentException) {
                    return null;
                }
                if (!seen.Add(target)) {
                    return null;
                }
                current = target;
            }
            return null;
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
