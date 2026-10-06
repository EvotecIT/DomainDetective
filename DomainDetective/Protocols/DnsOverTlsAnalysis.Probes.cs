using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class DnsOverTlsAnalysis {
    private async Task<(DnsAnswer[] Answers, string? Error)> DiscoverAsync(string name, DnsRecordType type,
        CancellationToken budget, CancellationToken caller) {
        try {
            budget.ThrowIfCancellationRequested();
            DnsResponse response;
            if (QueryDnsOverride != null) {
                var answers = await QueryDnsOverride(name, type).WaitWithCancellation(budget).ConfigureAwait(false);
                response = new DnsResponse { Status = DnsResponseCode.NoError, Answers = answers };
            } else {
                response = await DnsConfiguration.QueryDNSResponse(name, type, cancellationToken: budget).ConfigureAwait(false);
            }
            caller.ThrowIfCancellationRequested();
            return response.Status == DnsResponseCode.NoError && string.IsNullOrEmpty(response.Error)
                ? (response.Answers.Where(answer => answer.Type == type).ToArray(), null)
                : (Array.Empty<DnsAnswer>(), response.Error ?? response.Status.ToString());
        } catch (Exception ex) when (caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            throw new OperationCanceledException(caller);
        } catch (Exception ex) when (!caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            return (Array.Empty<DnsAnswer>(), budget.IsCancellationRequested ? "Analysis budget exhausted during discovery." : ex.Message);
        }
    }

    private async Task<DnsOverTlsEndpointResult> RunProbeAsync(string host, IPAddress ip, string zone,
        CancellationToken budget, CancellationToken caller) {
        bool attempted = false;
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(budget);
        deadline.CancelAfter(Timeout);
        DnsOverTlsEndpointResult result;
        try {
            deadline.Token.ThrowIfCancellationRequested();
            attempted = true;
            result = ProbeOverride != null
                ? await ProbeOverride(host, ip, Port, Timeout, deadline.Token).ConfigureAwait(false)
                : await ProbeDefaultAsync(host, ip, zone, deadline.Token, caller).ConfigureAwait(false);
            caller.ThrowIfCancellationRequested();
            if (result.Supported) result = result with { Outcome = DnsOverTlsProbeOutcome.Supported };
            else if (budget.IsCancellationRequested) result = result with { Outcome = DnsOverTlsProbeOutcome.BudgetExhausted };
        } catch (Exception ex) when (caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            throw new OperationCanceledException(caller);
        } catch (Exception ex) when (!caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            bool tlsStage = ex is TlsProbe.TlsProbeException;
            var socket = FindCause<SocketException>(ex);
            var outcome = budget.IsCancellationRequested ? DnsOverTlsProbeOutcome.BudgetExhausted
                : deadline.IsCancellationRequested || FindCause<TimeoutException>(ex) != null || FindCause<OperationCanceledException>(ex) != null
                    ? DnsOverTlsProbeOutcome.TimedOut
                    : tlsStage ? DnsOverTlsProbeOutcome.HandshakeFailed
                    : socket?.SocketErrorCode == SocketError.ConnectionRefused ? DnsOverTlsProbeOutcome.ConnectionRefused
                    : DnsOverTlsProbeOutcome.Failed;
            result = new DnsOverTlsEndpointResult {
                Outcome = outcome, FailureStage = !attempted ? "budget" : tlsStage ? "TLS handshake" : "connect", Error = ex.Message
            };
        }
        caller.ThrowIfCancellationRequested();
        return result with {
            NameServerHost = host, ServerIp = ip.ToString(), Port = Port, Attempted = attempted,
            ElapsedMilliseconds = watch.ElapsedMilliseconds
        };
    }

    private async Task<DnsOverTlsEndpointResult> ProbeDefaultAsync(string host, IPAddress ip, string zone,
        CancellationToken deadline, CancellationToken caller) {
        using var tls = await TlsProbe.ProbeWithFailureEvidenceAsync(ip, host, Port, Timeout, deadline).ConfigureAwait(false);
        var evidence = new DnsOverTlsEndpointResult {
            TlsHandshakeSucceeded = true, Protocol = tls.Protocol.ToString(), CipherSuite = tls.CipherSuite,
            HostnameMatch = tls.HostnameMatch, CertificateValid = tls.CertificateValid
        };
        try {
            var configuration = new DnsClientX.Configuration(ip.ToString(), DnsRequestFormat.DnsOverTLS) {
                Port = Port, TlsServerName = host, RecursionDesired = false,
                TimeOut = (int)Math.Min(int.MaxValue, Math.Max(1, Timeout.TotalMilliseconds)), UseTcpFallback = false
            };
            // Availability inspection matches TlsProbe's certificate policy. Certificate trust
            // is reported separately; a protocol response does not establish an authenticated resolver.
            using var client = new ClientX(configuration, ignoreCertificateErrors: true, enableCache: false);
            var response = await client.Resolve(zone, DnsRecordType.SOA, retryOnTransient: false,
                cancellationToken: deadline).ConfigureAwait(false);
            caller.ThrowIfCancellationRequested();
            bool verified = string.IsNullOrEmpty(response.Error);
            return evidence with {
                Supported = verified, DnsExchangeVerified = verified,
                Outcome = verified ? DnsOverTlsProbeOutcome.Supported : DnsOverTlsProbeOutcome.DnsExchangeFailed,
                FailureStage = verified ? null : "DNS exchange", Error = response.Error
            };
        } catch (Exception ex) when (!caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            return evidence with {
                Outcome = deadline.IsCancellationRequested || FindCause<TimeoutException>(ex) != null
                    ? DnsOverTlsProbeOutcome.TimedOut : DnsOverTlsProbeOutcome.DnsExchangeFailed,
                FailureStage = "DNS exchange", Error = ex.Message
            };
        }
    }

    private static T? FindCause<T>(Exception exception) where T : Exception {
        for (Exception? current = exception; current != null; current = current.InnerException) {
            if (current is T match) return match;
        }
        return null;
    }
}
