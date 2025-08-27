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
public class WildcardDnsAnalysis : IHasAssessments
{
    /// <summary>Names that were queried.</summary>
    public List<string> TestedNames { get; private set; } = new();
    /// <summary>Names that returned a record.</summary>
    public List<string> ResolvedNames { get; private set; } = new();
    /// <summary>Unique IP addresses returned for tested names.</summary>
    public List<string> ResolvedAddresses { get; private set; } = new();
    /// <summary>Whether all random names resolved.</summary>
    public bool CatchAll { get; private set; }

    /// <summary>Minimum fraction of matching results required.</summary>
    public double ConsistencyThreshold { get; set; } = 1.0;
    /// <summary>Number of attempts for each query.</summary>
    public int RetryCount { get; set; } = 1;

    /// <summary>Whether the domain has an SOA record.</summary>
    public bool SoaExists { get; private set; }
    /// <summary>Whether the domain has NS records.</summary>
    public bool NsExists { get; private set; }

    /// <summary>Configuration used for DNS lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>
    /// Optional DNS query delegate for testing purposes.
    /// </summary>
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
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "WILDCARD", target: domainName);
        TestedNames.Clear();
        ResolvedNames.Clear();
        ResolvedAddresses.Clear();
        CatchAll = false;
        SoaExists = false;
        NsExists = false;

        var soa = await QueryDns(domainName, DnsRecordType.SOA);
        SoaExists = soa.Length > 0;
        if (!SoaExists)
        {
            var ns = await QueryDns(domainName, DnsRecordType.NS);
            NsExists = ns.Length > 0;
        }

        var addressCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
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
                var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int attempt = 0; attempt < RetryCount; attempt++)
                {
                    var records = await QueryDns(name, DnsRecordType.A);
                    if (records.Length == 0)
                    {
                        records = await QueryDns(name, DnsRecordType.AAAA);
                    }

                    foreach (var rec in records)
                    {
                        var data = rec.DataRaw ?? string.Empty;
                        if (IPAddress.TryParse(data, out var ip))
                        {
                            data = ip.ToString();
                        }

                        if (!string.IsNullOrEmpty(data))
                        {
                            addresses.Add(data);
                        }
                    }
                }

                if (addresses.Count > 0)
                {
                    ResolvedNames.Add(name);
                    foreach (var addr in addresses)
                    {
                        if (!ResolvedAddresses.Contains(addr, StringComparer.OrdinalIgnoreCase))
                        {
                            ResolvedAddresses.Add(addr);
                        }

                        if (addressCount.ContainsKey(addr))
                        {
                            addressCount[addr]++;
                        }
                        else
                        {
                            addressCount[addr] = 1;
                        }
                    }
                }
            }
        }

        int required = (int)Math.Ceiling(TestedNames.Count * ConsistencyThreshold);
        CatchAll = ResolvedNames.Count >= required && addressCount.Values.Any(c => c >= required);
        logger?.WriteVerbose("Wildcard DNS for {0}: {1}", domainName, CatchAll);
        if (CatchAll)
        {
            logger?.WriteWarningCode(WildcardCodes.Enabled, "Wildcard DNS detected for {0}", domainName);
        }
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
