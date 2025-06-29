using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Inspects IMAP servers for TLS configuration details.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class IMAPTLSAnalysis : MailTlsAnalysis
{
    /// <summary>Analyzes a single IMAP server.</summary>
    public Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServer(MailProtocol.Imap, host, port, logger, cancellationToken);

    /// <summary>Analyzes multiple IMAP servers.</summary>
    public Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServers(MailProtocol.Imap, hosts, port, logger, cancellationToken);
}
