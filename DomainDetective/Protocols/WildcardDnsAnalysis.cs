using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Detects wildcard DNS configurations by querying random subdomains.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class WildcardDnsAnalysis
{
    /// <summary>Names that were queried.</summary>
    public List<string> TestedNames { get; private set; } = new();
    /// <summary>Names that returned a record.</summary>
    public List<string> ResolvedNames { get; private set; } = new();
    /// <summary>Whether all random names resolved.</summary>
    public bool CatchAll { get; private set; }

    public DnsConfiguration DnsConfiguration { get; set; } = new();
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type);
    }

    /// <summary>
    /// Queries random subdomains and detects wildcard DNS behaviour.
    /// </summary>
    /// <param name="domainName">Domain to analyze.</param>
    /// <param name="logger">Optional logger used for diagnostics.</param>
    /// <param name="sampleCount">Number of random names to test.</param>
    public async Task Analyze(string domainName, InternalLogger logger, int sampleCount = 3)
    {
        TestedNames.Clear();
        ResolvedNames.Clear();
        CatchAll = false;

        for (int i = 0; i < sampleCount; i++)
        {
            string sub = $"{Guid.NewGuid():N}.{domainName}";
            TestedNames.Add(sub);
            var records = await QueryDns(sub, DnsRecordType.A);
            if (records.Length > 0)
            {
                ResolvedNames.Add(sub);
            }
        }

        CatchAll = ResolvedNames.Count == TestedNames.Count;
        logger?.WriteVerbose("Wildcard DNS for {0}: {1}", domainName, CatchAll);
    }
}
