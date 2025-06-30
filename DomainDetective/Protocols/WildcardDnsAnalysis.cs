using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
    /// <summary>Unique IP addresses returned for tested names.</summary>
    public List<string> ResolvedAddresses { get; private set; } = new();
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
        ResolvedAddresses.Clear();
        CatchAll = false;

        const int depthToCheck = 2;
        for (int i = 0; i < sampleCount; i++)
        {
            for (int depth = 1; depth <= depthToCheck; depth++)
            {
                string name = domainName;
                for (int j = 0; j < depth; j++)
                {
                    name = $"{Guid.NewGuid():N}.{name}";
                }

                TestedNames.Add(name);
                var records = await QueryDns(name, DnsRecordType.A);
                if (records.Length == 0)
                {
                    records = await QueryDns(name, DnsRecordType.AAAA);
                }

                if (records.Length > 0)
                {
                    ResolvedNames.Add(name);

                    foreach (var rec in records)
                    {
                        var data = rec.DataRaw ?? string.Empty;
                        if (IPAddress.TryParse(data, out var ip))
                        {
                            data = ip.ToString();
                        }

                        if (!string.IsNullOrEmpty(data) && !ResolvedAddresses.Contains(data, StringComparer.OrdinalIgnoreCase))
                        {
                            ResolvedAddresses.Add(data);
                        }
                    }
                }
            }
        }

        CatchAll = ResolvedNames.Count == TestedNames.Count;
        logger?.WriteVerbose("Wildcard DNS for {0}: {1}", domainName, CatchAll);
    }
}
