using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
        public List<string> PtrRecords { get; set; } = new();
        public string? PtrRecord => PtrRecords.FirstOrDefault();
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
            var ptrs = item.PtrRecords;
            if (ptrs.Count == 0 && !string.IsNullOrWhiteSpace(item.PtrRecord))
            {
                ptrs = new List<string> { item.PtrRecord.TrimEnd('.') };
            }

            if (ptrs.Count == 0 && IPAddress.TryParse(item.IpAddress, out var ip) &&
                ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var ptrName = ip.ToPtrFormat() + ".ip6.arpa";
                var answers = await QueryDns(ptrName, DnsRecordType.PTR);
                ptrs = answers.Select(a => a.Data.TrimEnd('.')).ToList();
                logger?.WriteVerbose($"FCrDNS PTR {ptrName} -> {string.Join(", ", ptrs)}");
            }

            bool match = false;
            foreach (var ptr in ptrs)
            {
                var normalizedPtr = ptr.TrimEnd('.');
                var a = await QueryDns(normalizedPtr, DnsRecordType.A);
                var aaaa = await QueryDns(normalizedPtr, DnsRecordType.AAAA);
                logger?.WriteVerbose($"FCrDNS {normalizedPtr} -> {string.Join(", ", a.Concat(aaaa).Select(r => r.Data))}");
                if (a.Concat(aaaa).Any(r => r.Data == item.IpAddress))
                {
                    match = true;
                    break;
                }
            }

            Results.Add(new FCrDnsResult
            {
                IpAddress = item.IpAddress,
                PtrRecords = ptrs.Select(p => p.TrimEnd('.')).ToList(),
                ForwardConfirmed = match
            });
        }
    }
}
