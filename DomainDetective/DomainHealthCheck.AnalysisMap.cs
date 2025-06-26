using System.Collections.Generic;
namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    ///     Creates a dictionary mapping each <see cref="HealthCheckType"/> to
    ///     the corresponding analysis result instance.
    /// </summary>
    /// <returns>
    ///     Read-only dictionary of health check results.
    /// </returns>
    public IReadOnlyDictionary<HealthCheckType, object?> GetAnalysisMap()
    {
        var map = new Dictionary<HealthCheckType, object?>
        {
            [HealthCheckType.DMARC] = DmarcAnalysis,
            [HealthCheckType.SPF] = SpfAnalysis,
            [HealthCheckType.DKIM] = DKIMAnalysis,
            [HealthCheckType.MX] = MXAnalysis,
            [HealthCheckType.CAA] = CAAAnalysis,
            [HealthCheckType.NS] = NSAnalysis,
            [HealthCheckType.DANE] = DaneAnalysis,
            [HealthCheckType.DNSBL] = DNSBLAnalysis,
            [HealthCheckType.DNSSEC] = DNSSecAnalysis,
            [HealthCheckType.MTASTS] = MTASTSAnalysis,
            [HealthCheckType.TLSRPT] = TLSRPTAnalysis,
            [HealthCheckType.BIMI] = BimiAnalysis,
            [HealthCheckType.CERT] = CertificateAnalysis,
            [HealthCheckType.SECURITYTXT] = SecurityTXTAnalysis,
            [HealthCheckType.SOA] = SOAAnalysis,
            [HealthCheckType.OPENRELAY] = OpenRelayAnalysis,
            [HealthCheckType.STARTTLS] = StartTlsAnalysis,
            [HealthCheckType.SMTPTLS] = SmtpTlsAnalysis,
            [HealthCheckType.HTTP] = HttpAnalysis,
            [HealthCheckType.HPKP] = HPKPAnalysis,
            [HealthCheckType.CONTACT] = ContactInfoAnalysis,
            [HealthCheckType.MESSAGEHEADER] = MessageHeaderAnalysis
        };

        return map;
    }
}
