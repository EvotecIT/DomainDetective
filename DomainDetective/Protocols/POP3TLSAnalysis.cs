using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Inspects POP3 servers for TLS configuration details.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class POP3TLSAnalysis : MailTlsAnalysis
{
    /// <summary>Analyzes a single POP3 server.</summary>
    public Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServer(MailProtocol.Pop3, host, port, logger, cancellationToken);

    /// <summary>Analyzes multiple POP3 servers.</summary>
    public Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
        => base.AnalyzeServers(MailProtocol.Pop3, hosts, port, logger, cancellationToken);
}
