using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private async Task ValidateDaneCertificateAssociationsAsync(CancellationToken cancellationToken) {
        var owners = DaneAnalysis.AnalysisResults
            .Where(record => record.ValidDANERecord && !string.IsNullOrWhiteSpace(record.DomainName))
            .Select(record => record.DomainName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (owners.Length == 0) {
            return;
        }

        // DNS test overrides commonly provide synthetic TLSA records without a
        // corresponding service. Callers can supply matching evidence explicitly.
        if (DaneDnsOverride != null && DaneCertificateEvidenceOverride == null) {
            return;
        }

        foreach (var owner in owners) {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryParseTlsaOwner(owner, out var host, out var port)) {
                continue;
            }

            DaneCertificateEvidence? evidence = null;
            var certificatesToDispose = new List<X509Certificate2>();
            try {
                if (DaneCertificateEvidenceOverride != null) {
                    evidence = await DaneCertificateEvidenceOverride(host, port, cancellationToken);
                    if (evidence != null) {
                        evidence.TlsaOwnerName = owner;
                    }
                } else {
                    var dnssec = new DnsSecAnalysis {
                        UseLocalDnssecValidation = DnsSecValidateLocally,
                        QueryDnsResponseOverride = DnsConfiguration.QueryDnsResponseOverride
                    };
                    await dnssec.AnalyzeRecord(owner, DnsRecordType.TLSA, _logger, DnsConfiguration, cancellationToken);

                    if (port == (int)ServiceType.SMTP) {
                        var mailTls = new MailTlsAnalysis { OutboundAddressResolver = OutboundAddressResolver };
                        await mailTls.AnalyzeServer(MailTlsAnalysis.MailProtocol.Smtp, host, port, _logger, cancellationToken);
                        mailTls.ServerResults.TryGetValue($"{host}:{port}", out var result);
                        evidence = new DaneCertificateEvidence {
                            TlsaOwnerName = owner,
                            EndEntityCertificate = result?.Certificate,
                            CertificateChain = result != null ? result.Chain : Array.Empty<X509Certificate2>(),
                            PkixValidated = result?.CertificateValid == true && result.ChainValid,
                            DnssecValidated = dnssec.ValidationStatus == DnssecValidationStatus.Secure
                        };
                        if (result?.Certificate != null) {
                            certificatesToDispose.Add(result.Certificate);
                        }
                        certificatesToDispose.AddRange(result?.Chain ?? Enumerable.Empty<X509Certificate2>());
                    } else {
                        using var tls = await ProbeDaneTlsAsync(host, port, cancellationToken).ConfigureAwait(false);
                        evidence = new DaneCertificateEvidence {
                            TlsaOwnerName = owner,
                            EndEntityCertificate = tls.Certificate,
                            CertificateChain = tls.Chain,
                            PkixValidated = tls.CertificateValid && tls.ChainValid,
                            DnssecValidated = dnssec.ValidationStatus == DnssecValidationStatus.Secure
                        };
                        DaneAnalysis.ValidateCertificateAssociations(new[] { evidence }, _logger);
                        evidence = null;
                    }
                }

                if (evidence != null) {
                    DaneAnalysis.ValidateCertificateAssociations(new[] { evidence }, _logger);
                }
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                _logger.WriteWarningCode(DaneCodes.CertificateCheckFailed, "Unable to collect certificate evidence for {0}: {1}", owner, ex.Message);
            } finally {
                foreach (var certificate in certificatesToDispose.Distinct()) {
                    certificate.Dispose();
                }
            }
        }
    }

    private async Task<TlsProbe.Result> ProbeDaneTlsAsync(string host, int port, CancellationToken cancellationToken) {
        if (OutboundAddressResolver == null) {
            return await TlsProbe.ProbeAsync(host, port, cancellationToken).ConfigureAwait(false);
        }

        var addresses = await OutboundAddressResolver(host, cancellationToken).ConfigureAwait(false);
        Exception? lastError = null;
        foreach (var address in addresses) {
            try {
                return await TlsProbe.ProbeAsync(address, host, port, cancellationToken).ConfigureAwait(false);
            } catch (Exception ex) when (ex is not OperationCanceledException) {
                lastError = ex;
            }
        }
        throw new InvalidOperationException($"No approved address accepted a TLS connection for {host}:{port}.", lastError);
    }

    private static bool TryParseTlsaOwner(string owner, out string host, out int port) {
        host = string.Empty;
        port = 0;
        var labels = owner.TrimEnd('.').Split('.');
        if (labels.Length < 4 || !labels[0].StartsWith("_", StringComparison.Ordinal) ||
            !int.TryParse(labels[0].Substring(1), out port) || port <= 0 ||
            (!labels[1].Equals("_tcp", StringComparison.OrdinalIgnoreCase) && !labels[1].Equals("_udp", StringComparison.OrdinalIgnoreCase))) {
            return false;
        }
        host = string.Join(".", labels.Skip(2));
        return host.Length > 0;
    }
}
