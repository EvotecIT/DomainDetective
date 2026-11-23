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
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; set; }
    /// <summary>DNS client configuration.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override for DNS queries during testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Represents forward confirmed result for a single address.</summary>
    public class FCrDnsResult
    {
        /// <summary>Gets or sets the ip address value.</summary>
        public string IpAddress { get; set; } = null!;
        /// <summary>Gets or sets the ptr records value.</summary>
        public List<string> PtrRecords { get; set; } = new();
        /// <summary>Represents the ptr record value.</summary>
        public string? PtrRecord => PtrRecords.FirstOrDefault();
        /// <summary>True when PTR hostname resolves to the original IP.</summary>
        public bool ForwardConfirmed { get; set; }

        /// <summary>True when a forward lookup of a PTR name returned at least one address.</summary>
        public bool ForwardAnswered { get; set; }

        /// <summary>
        /// True when no PTR record was found because the PTR lookup itself failed, so the missing record is unknown rather
        /// than confirmed.
        /// </summary>
        public bool PtrLookupFailed { get; set; }
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

    // A forward lookup with whether it answered conclusively; an empty array alone cannot tell "no record" from a failure.
    private async Task<(DnsAnswer[] Answers, bool Conclusive)> QueryForward(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return (await QueryDnsOverride(name, type), true);
        }
        DnsResponse response = await DnsConfiguration.QueryDNSResponse(name, type);
        bool conclusive = string.IsNullOrEmpty(response.Error)
            && (response.Status == DnsResponseCode.NoError || response.Status == DnsResponseCode.NXDomain);
        return (response.Answers ?? Array.Empty<DnsAnswer>(), conclusive);
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
            var ptrRecord = item.PtrRecord;
            if (ptrs.Count == 0 && ptrRecord != null && !string.IsNullOrWhiteSpace(ptrRecord))
            {
                ptrs = new List<string> { ptrRecord.TrimEnd('.') };
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
            // A mismatch is settled only when every PTR name's forward lookup answered: an unanswered one could still
            // point back to the address.
            bool answered = ptrs.Count > 0;
            bool isIpv6 = IPAddress.TryParse(item.IpAddress, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6;
            foreach (var ptr in ptrs)
            {
                var normalizedPtr = ptr.TrimEnd('.');
                var (a, aConclusive) = await QueryForward(normalizedPtr, DnsRecordType.A);
                var (aaaa, aaaaConclusive) = await QueryForward(normalizedPtr, DnsRecordType.AAAA);
                // Only the lookup for the address's own family can confirm it: when that lookup failed, an answer of the
                // other family does not settle a mismatch.
                // NXDOMAIN or no data for the family is a conclusive "does not point back"; SERVFAIL and timeouts are not.
                answered &= isIpv6 ? aaaaConclusive : aConclusive;
                logger?.WriteVerbose($"FCrDNS {normalizedPtr} -> {string.Join(", ", a.Concat(aaaa).Select(r => r.Data))}");
                if (a.Concat(aaaa).Any(r => SameAddress(r.Data, address, item.IpAddress)))
                {
                    match = true;
                    break;
                }
            }

            Results.Add(new FCrDnsResult
            {
                IpAddress = item.IpAddress,
                PtrRecords = ptrs.Select(p => p.TrimEnd('.')).ToList(),
                ForwardConfirmed = match,
                ForwardAnswered = answered || match,
                PtrLookupFailed = item.PtrLookupFailed && ptrs.Count == 0
            });
        }
    }

    // 2001:db8::1 and 2001:0db8:0:0:0:0:0:1 are the same address, so compare parsed addresses when both sides parse.
    private static bool SameAddress(string? answer, IPAddress? expected, string? raw) =>
        expected != null && IPAddress.TryParse(answer?.Trim(), out var parsed)
            ? parsed.Equals(expected)
            : string.Equals(answer, raw, StringComparison.OrdinalIgnoreCase);
}
