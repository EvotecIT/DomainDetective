using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Validates that PTR hostnames resolve back to their originating IP.
/// </summary>
public class FCrDnsAnalysis
{
    /// <summary>DNS client configuration.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override for DNS queries during testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Represents forward confirmed result for a single address.</summary>
    public class FCrDnsResult
    {
        public string IpAddress { get; set; }
        public string? PtrRecord { get; set; }
        /// <summary>True when PTR hostname resolves to the original IP.</summary>
        public bool ForwardConfirmed { get; set; }
    }

    /// <summary>Collection of results for each IP.</summary>
    public List<FCrDnsResult> Results { get; private set; } = new();
    /// <summary>Indicates whether every address passed forward confirmation.</summary>
    public bool AllValid => Results.All(r => r.ForwardConfirmed);

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    /// <summary>
    /// Validates that each PTR record in <paramref name="reverseResults"/> resolves back to its IP.
    /// </summary>
    public async Task Analyze(IEnumerable<ReverseDnsAnalysis.ReverseDnsResult> reverseResults, InternalLogger? logger = null)
    {
        Results = new List<FCrDnsResult>();
        foreach (var item in reverseResults)
        {
            if (string.IsNullOrWhiteSpace(item.PtrRecord))
            {
                Results.Add(new FCrDnsResult { IpAddress = item.IpAddress, PtrRecord = item.PtrRecord, ForwardConfirmed = false });
                continue;
            }

            var normalizedPtr = item.PtrRecord.TrimEnd('.');

            var a = await QueryDns(normalizedPtr, DnsRecordType.A);
            var aaaa = await QueryDns(normalizedPtr, DnsRecordType.AAAA);
            bool match = a.Concat(aaaa).Any(r => r.Data == item.IpAddress);
            logger?.WriteVerbose($"FCrDNS {normalizedPtr} -> {string.Join(", ", a.Concat(aaaa).Select(r => r.Data))}");
            Results.Add(new FCrDnsResult
            {
                IpAddress = item.IpAddress,
                PtrRecord = normalizedPtr,
                ForwardConfirmed = match
            });
        }
    }
}
