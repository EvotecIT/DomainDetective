using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Inspects SMTP servers for TLS configuration details.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class SMTPTLSAnalysis : MailTlsAnalysis
{
    /// <summary>Analyzes a single SMTP server.</summary>
    public Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServer(MailProtocol.Smtp, host, port, logger, cancellationToken);

    /// <summary>Analyzes multiple SMTP servers.</summary>
    public Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServers(MailProtocol.Smtp, hosts, port, logger, cancellationToken);
}
