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

        private async Task<(DnsAnswer[] Records, DnsSecValidationStatus Status)> QueryDaneDns(string name, CancellationToken cancellationToken) {
            try {
                if (DaneAnalysis.QueryDnsOverride != null) {
                    return (DANEAnalysis.BindServiceTlsaAnswers(name,
                        await DaneAnalysis.QueryDnsOverride(name, DnsRecordType.TLSA)), DnsSecValidationStatus.NotRequested);
                }

                DnsResponse? response = DnsConfiguration.QueryDnsOverride == null
                    ? await DnsSecAnalysis.QueryValidatedSubjectResponseAsync(name, DnsRecordType.TLSA, DnsConfiguration, cancellationToken)
                    : (await DnsConfiguration.QueryFullDNSOrdered(new[] { name }, DnsRecordType.TLSA,
                        cancellationToken: cancellationToken))[0];
                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                    DaneAnalysis.RecordDnsQueryFailure(name, DescribeDaneDnsFailure(response), _logger);
                    return (Array.Empty<DnsAnswer>(), DnsSecValidationStatus.Indeterminate);
                }
                DnsAnswer[] records = DANEAnalysis.BindServiceTlsaAnswers(name, response);
                if (response.DnsSecValidationStatus == DnsSecValidationStatus.Bogus ||
                    response.DnsSecValidationStatus == DnsSecValidationStatus.Indeterminate ||
                    response.DnsSecValidationStatus == DnsSecValidationStatus.NotRequested && records.Length == 0) {
                    DaneAnalysis.RecordDnsQueryFailure(name, $"DNSSEC validation is {response.DnsSecValidationStatus}", _logger);
                    return (Array.Empty<DnsAnswer>(), response.DnsSecValidationStatus);
                }
                // A positive unvalidated RRset can still be reported, but a later
                // certificate check must validate the exact data before authentication.
                return (records, response.DnsSecValidationStatus);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception exception) when (exception is TimeoutException ||
                exception is TaskCanceledException || exception is System.Net.Http.HttpRequestException) {
                DaneAnalysis.RecordDnsQueryFailure(name, exception.Message, _logger);
                return (Array.Empty<DnsAnswer>(), DnsSecValidationStatus.Indeterminate);
            }
        }

        private async Task<DnsAnswer[]> QueryDaneServiceAsync(string host, int port,
            Dictionary<string, (string? Target, bool Failed)> secureAliases, CancellationToken cancellationToken) {
            host = NormalizeDomain(host).TrimEnd('.');
            if (!secureAliases.TryGetValue(host, out var alias)) {
                alias = await ResolveSecureDaneHostAliasAsync(host, cancellationToken);
                secureAliases.Add(host, alias);
            }
            if (alias.Failed) {
                return Array.Empty<DnsAnswer>();
            }

            if (alias.Target != null) {
                string targetOwner = CreateServiceQuery(port, alias.Target);
                RecordDaneQueryName(targetOwner);
                var targetQuery = await QueryDaneDns(targetOwner, cancellationToken);
                if (targetQuery.Status == DnsSecValidationStatus.Secure && targetQuery.Records.Length > 0) {
                    DaneAnalysis.SelectServiceOwner(targetOwner, secureTlsaRecords: true);
                    return targetQuery.Records;
                }
                if (targetQuery.Status == DnsSecValidationStatus.NotRequested) {
                    DaneAnalysis.RecordDnsQueryFailure(targetOwner, "TLSA DNSSEC validation was not available", _logger);
                    return Array.Empty<DnsAnswer>();
                }
                if (targetQuery.Status != DnsSecValidationStatus.Insecure &&
                    targetQuery.Status != DnsSecValidationStatus.Secure) {
                    return Array.Empty<DnsAnswer>();
                }
            }

            string originalOwner = CreateServiceQuery(port, host);
            RecordDaneQueryName(originalOwner);
            var originalQuery = await QueryDaneDns(originalOwner, cancellationToken);
            DaneAnalysis.SelectServiceOwner(originalOwner,
                secureTlsaRecords: originalQuery.Status == DnsSecValidationStatus.Secure && originalQuery.Records.Length > 0);
            return originalQuery.Records;
        }

        private void RecordDaneQueryName(string name) {
            if (!DaneAnalysis.QueriedNames.Contains(name, StringComparer.OrdinalIgnoreCase)) {
                DaneAnalysis.QueriedNames.Add(name);
            }
        }

        private async Task<(string? Target, bool Failed)> ResolveSecureDaneHostAliasAsync(string host, CancellationToken cancellationToken) {
            // Answer-only overrides cannot establish that a CNAME hop is DNSSEC Secure.
            if (DnsConfiguration.QueryDnsResponseOverride == null &&
                (DaneDnsOverride != null || DnsConfiguration.QueryDnsOverride != null)) {
                return (null, false);
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
                    return (null, true);
                }

                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                    DaneAnalysis.RecordDnsQueryFailure(current, DescribeDaneDnsFailure(response), _logger);
                    return (null, true);
                }
                if (response.DnsSecValidationStatus == DnsSecValidationStatus.Insecure) {
                    return (null, false);
                }
                if (response.DnsSecValidationStatus != DnsSecValidationStatus.Secure) {
                    DaneAnalysis.RecordDnsQueryFailure(current, $"DNSSEC validation is {response.DnsSecValidationStatus}", _logger);
                    return (null, true);
                }

                DnsAnswer[] cnames = (response.Answers ?? Array.Empty<DnsAnswer>())
                    .Where(answer => answer.Type == DnsRecordType.CNAME &&
                        string.Equals(answer.Name?.TrimEnd('.'), current, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (cnames.Length == 0) {
                    return (hop == 0 ? null : current, false);
                }
                if (cnames.Length != 1 || hop == MaxDaneHostAliasHops) {
                    DaneAnalysis.RecordDnsQueryFailure(current, "CNAME expansion is ambiguous or exceeds the hop limit", _logger);
                    return (null, true);
                }

                string target;
                try {
                    target = NormalizeDomain(cnames[0].Data ?? cnames[0].DataRaw).TrimEnd('.');
                } catch (ArgumentException) {
                    DaneAnalysis.RecordDnsQueryFailure(current, "CNAME target is invalid", _logger);
                    return (null, true);
                }
                if (!seen.Add(target)) {
                    DaneAnalysis.RecordDnsQueryFailure(current, "CNAME expansion contains a loop", _logger);
                    return (null, true);
                }
                current = target;
            }
            return (null, false);
        }

        private async Task<DnsAnswer[]> QueryDaneMxDns(string domainName, CancellationToken cancellationToken) {
            try {
                bool answerOnlyOverride = DnsConfiguration.QueryDnsResponseOverride == null &&
                    DnsConfiguration.QueryDnsOverride != null;
                DnsResponse? response = answerOnlyOverride
                    ? (await DnsConfiguration.QueryFullDNSOrdered(new[] { domainName }, DnsRecordType.MX,
                        cancellationToken: cancellationToken))[0]
                    : await DnsSecAnalysis.QueryValidatedSubjectResponseAsync(
                        domainName, DnsRecordType.MX, DnsConfiguration, cancellationToken);
                if (response == null || !string.IsNullOrEmpty(response.Error) ||
                    response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                    DaneAnalysis.RecordDnsQueryFailure(domainName, DescribeDaneDnsFailure(response), _logger);
                    return Array.Empty<DnsAnswer>();
                }
                if (response.DnsSecValidationStatus == DnsSecValidationStatus.Bogus ||
                    response.DnsSecValidationStatus == DnsSecValidationStatus.Indeterminate ||
                    response.DnsSecValidationStatus == DnsSecValidationStatus.NotRequested && !answerOnlyOverride) {
                    DaneAnalysis.RecordDnsQueryFailure(domainName, $"MX DNSSEC validation is {response.DnsSecValidationStatus}", _logger);
                    return Array.Empty<DnsAnswer>();
                }
                DaneAnalysis.MxDnssecValidated = response.DnsSecValidationStatus == DnsSecValidationStatus.Secure;
                if (DaneAnalysis.MxDnssecValidated != true) {
                    _logger.WriteWarningCode(DaneCodes.MxNotAuthenticated,
                        "MX service selection for {0} was not DNSSEC authenticated; TLSA matches cannot authenticate delivery to this domain.", domainName);
                }
                if (answerOnlyOverride) {
                    return response.Answers ?? Array.Empty<DnsAnswer>();
                }
                return BindDaneMxAnswers(domainName, response);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch (Exception exception) when (exception is TimeoutException ||
                exception is TaskCanceledException || exception is System.Net.Http.HttpRequestException) {
                DaneAnalysis.RecordDnsQueryFailure(domainName, exception.Message, _logger);
                return Array.Empty<DnsAnswer>();
            }
        }

        private static DnsAnswer[] BindDaneMxAnswers(string domainName, DnsResponse response) {
            DnsAnswer[] mxRecords = (response.Answers ?? Array.Empty<DnsAnswer>())
                .Where(answer => answer.Type == DnsRecordType.MX && !string.IsNullOrWhiteSpace(answer.Name))
                .ToArray();
            DnsAnswer[] direct = mxRecords.Where(answer =>
                string.Equals(answer.Name.TrimEnd('.'), domainName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)).ToArray();
            if (direct.Length > 0) {
                return direct;
            }

            // DnsClientX sets this only after validating the complete answer's
            // alias chain, before projecting CNAME/DNAME records from MX results.
            return response.RequestedAnswerPresent && mxRecords.Length > 0 &&
                mxRecords.Select(answer => answer.Name.TrimEnd('.'))
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1
                ? mxRecords : Array.Empty<DnsAnswer>();
        }

        private static string DescribeDaneDnsFailure(DnsResponse? response) {
            string? error = response?.Error;
            if (error != null && error.Length > 0) return error;
            return response == null ? "no resolver response" : response.Status.ToString();
        }
    }
}
