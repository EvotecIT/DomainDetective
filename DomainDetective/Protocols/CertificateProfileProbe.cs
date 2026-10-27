using System;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>Routes certificate collection through the existing protocol engines without authentication.</summary>
public static class CertificateProfileProbe {
    /// <summary>Collects one profile observation. The caller owns and disposes the returned certificate evidence.</summary>
    public static async Task<TlsProbe.Result> ProbeAsync(string host, CertificateProbeProfile profile, TimeSpan timeout, CancellationToken cancellationToken = default) {
        if (profile == null) throw new ArgumentNullException(nameof(profile));
        profile.Validate();
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(timeout));
        TlsProbe.Result result;
        if (profile.Transport == CertificateProbeTransport.DirectTls) {
            result = await TlsProbe.ProbeWithFailureEvidenceAsync(host, profile.Port, timeout, cancellationToken).ConfigureAwait(false);
        } else if (profile.Transport == CertificateProbeTransport.SmtpStartTls) {
            var analysis = new MailTlsAnalysis { Timeout = timeout, ConnectTimeout = timeout, ProbeProtocolSupportEnabled = false, ProbeOcspStaplingEnabled = false };
            await analysis.AnalyzeServer(MailTlsAnalysis.MailProtocol.Smtp, host, profile.Port, new InternalLogger(), cancellationToken).ConfigureAwait(false);
            MailTlsAnalysis.TlsResult mail = analysis.ServerResults.Values.Single();
            try {
                RequireNegotiated(mail.Certificate, mail.Protocol, mail.FailureKind, mail.FailureReason, mail.Connection.RemoteAddress, profile.Port);
                result = Copy(mail.Certificate!, mail.Protocol, mail.CertificateValid, mail.HostnameMatch, mail.ChainErrors, mail.Chain, mail.Connection.RemoteAddress, profile.Port);
                result.CipherSuite = mail.CipherSuite;
            } finally {
                mail.Certificate?.Dispose();
                foreach (X509Certificate2 certificate in mail.Chain) certificate.Dispose();
            }
        } else {
            using FtpTlsResult ftp = await new FtpTlsAnalysis { Timeout = timeout }.AnalyzeAsync(
                new FtpTlsEndpoint(host, profile.Port, profile.Transport == CertificateProbeTransport.FtpExplicitTls ? FtpTlsMode.Explicit : FtpTlsMode.Implicit), new InternalLogger(), cancellationToken).ConfigureAwait(false);
            RequireNegotiated(ftp.Certificate, ftp.Protocol, ftp.FailureKind, ftp.FailureReason, ftp.Connection.RemoteAddress, profile.Port);
            result = Copy(ftp.Certificate!, ftp.Protocol, ftp.CertificateValid, ftp.HostnameMatch, ftp.ChainErrors, ftp.Chain, ftp.Connection.RemoteAddress, profile.Port);
        }
        result.ProfileId = profile.Id;
        result.EndpointService = profile.Service;
        if (result.RemoteAddress?.IsIPv4MappedToIPv6 == true) result.RemoteAddress = result.RemoteAddress.MapToIPv4();
        return result;
    }

    private static void RequireNegotiated(X509Certificate2? certificate, SslProtocols protocol, CertificateFailureKind kind, string? failure, string? address, int port) {
        if (certificate != null && protocol != SslProtocols.None && string.IsNullOrWhiteSpace(failure)) return;
        var error = new AuthenticationException(failure ?? "The endpoint did not negotiate the requested TLS service.");
        bool connected = IPAddress.TryParse(address, out IPAddress? ip);
        throw new TlsProbe.TlsProbeException(error.Message, error, connected ? ip : null, connected ? port : null) {
            FailureKind = kind == CertificateFailureKind.None ? CertificateFailureKind.TlsHandshake : kind
        };
    }

    private static TlsProbe.Result Copy(X509Certificate2 certificate, SslProtocols protocol, bool valid, bool hostnameMatch,
        System.Collections.Generic.IEnumerable<X509ChainStatusFlags> errors, System.Collections.Generic.IEnumerable<X509Certificate2> chain, string? address, int port) {
        var result = new TlsProbe.Result { Certificate = CertificateLoaderCompat.Clone(certificate), Protocol = protocol, CertificateValid = valid,
            HostnameMatch = hostnameMatch, CertificateSubject = certificate.Subject, CertificateIssuer = certificate.Issuer,
            NotBefore = certificate.NotBefore, NotAfter = certificate.NotAfter, RemoteAddress = IPAddress.TryParse(address, out IPAddress? ip) ? ip : null, RemotePort = port };
        result.ChainErrors.AddRange(errors);
        result.Chain.AddRange(chain.Select(CertificateLoaderCompat.Clone));
        result.DnsNames.AddRange(TlsProbe.ExtractCertificateDnsNames(certificate, out string? error));
        result.SanParsingError = error;
        return result;
    }
}
