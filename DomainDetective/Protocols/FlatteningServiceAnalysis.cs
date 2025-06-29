using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Detects if CNAME records point to known flattening services like Cloudflare.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class FlatteningServiceAnalysis
{
    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override DNS query logic.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Indicates whether a CNAME record exists.</summary>
    public bool CnameRecordExists { get; private set; }
    /// <summary>The target of the CNAME record.</summary>
    public string? Target { get; private set; }
    /// <summary>True when the CNAME points to a known flattening service.</summary>
    public bool IsFlatteningService { get; private set; }

    private static readonly string[] _flatteningDomains = new[]
    {
        "cloudflare.net"
    };

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// Queries the domain CNAME and determines if it belongs to a flattening service.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        CnameRecordExists = false;
        Target = null;
        IsFlatteningService = false;
        ct.ThrowIfCancellationRequested();

        var cname = await QueryDns(domainName, DnsRecordType.CNAME, ct);
        if (cname == null || cname.Length == 0)
        {
            logger?.WriteVerbose("No CNAME record found.");
            return;
        }

        Target = cname[0].Data.TrimEnd('.');
        CnameRecordExists = true;
        logger?.WriteVerbose("CNAME target {0}", Target);

        IsFlatteningService = _flatteningDomains.Any(d => Target.EndsWith(d, StringComparison.OrdinalIgnoreCase));
        if (IsFlatteningService)
        {
            logger?.WriteWarning("CNAME uses a known flattening service");
        }
    }
}
