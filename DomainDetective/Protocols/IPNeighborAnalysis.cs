using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Collects domains resolving to the same IP address using PTR and passive DNS.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class IPNeighborAnalysis
{
    /// <summary>DNS configuration used for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Override for DNS queries during testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
    /// <summary>Override for passive DNS lookups.</summary>
    public Func<string, Task<List<string>>>? PassiveDnsLookupOverride { private get; set; }

    /// <summary>Results keyed by IP address.</summary>
    public List<IPNeighborResult> Results { get; private set; } = new();
    /// <summary>Errors encountered during analysis.</summary>
    public List<Exception> Errors { get; private set; } = new();
    /// <summary>Override for RPKI validity checks.</summary>
    public Func<string, Task<bool>>? RPKIValidationOverride { private get; set; }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    private async Task<List<string>> QueryPassiveDns(string ip, InternalLogger logger)
    {
        if (PassiveDnsLookupOverride != null)
        {
            return await PassiveDnsLookupOverride(ip);
        }

        try
        {
            using var client = new HttpClient();
            var url = $"https://api.hackertarget.com/reverseiplookup/?q={ip}";
            using var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
            {
                return new List<string>();
            }
            var text = await resp.Content.ReadAsStringAsync();
        var domains = text.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(d => d.Trim())
                .Where(d => d.Length > 0 && !d.StartsWith("error", StringComparison.OrdinalIgnoreCase))
                .ToList();
            return domains;
        }
        catch (Exception ex)
        {
            logger?.WriteError("Passive DNS query failed for {0}: {1}", ip, ex.Message);
            return new List<string>();
        }
    }

    private async Task<bool> QueryRpki(string ip, InternalLogger logger)
    {
        if (RPKIValidationOverride != null)
        {
            return await RPKIValidationOverride(ip);
        }

        try
        {
            using var client = new HttpClient();
            var prefixResp = await client.GetAsync($"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}");
            prefixResp.EnsureSuccessStatusCode();
            using var prefixStream = await prefixResp.Content.ReadAsStreamAsync();
            var prefixDoc = await JsonDocument.ParseAsync(prefixStream);
            var prefix = prefixDoc.RootElement.GetProperty("data").GetProperty("resource").GetString();
            var asn = prefixDoc.RootElement.GetProperty("data").GetProperty("asns")[0].GetProperty("asn").GetInt32();
            var rpkiUrl = $"https://stat.ripe.net/data/rpki-validation/data.json?prefix={prefix}&resource=AS{asn}";
            using var rpkiResp = await client.GetAsync(rpkiUrl);
            rpkiResp.EnsureSuccessStatusCode();
            using var rpkiStream = await rpkiResp.Content.ReadAsStreamAsync();
            var rpkiDoc = await JsonDocument.ParseAsync(rpkiStream);
            var status = rpkiDoc.RootElement.GetProperty("data").GetProperty("status").GetString();
            return !string.Equals(status, "invalid", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            logger?.WriteError("RPKI query failed for {0}: {1}", ip, ex.Message);
            return true;
        }
    }

    /// <summary>
    /// Queries PTR and passive DNS for all IPs of <paramref name="domainName"/>.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        Results = new List<IPNeighborResult>();
        Errors = new List<Exception>();
        var answers = await QueryDns(domainName, DnsRecordType.A);
        var aaaa = await QueryDns(domainName, DnsRecordType.AAAA);

        var tasks = answers.Concat(aaaa).Select(async record =>
        {
            ct.ThrowIfCancellationRequested();
            if (!IPAddress.TryParse(record.Data, out var ip))
            {
                return;
            }

            var ipStr = ip.ToString();
            var ptrName = ip.ToPtrFormat() + (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? ".ip6.arpa" : ".in-addr.arpa");
            var list = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                var ptr = await QueryDns(ptrName, DnsRecordType.PTR);
                if (ptr.Length > 0)
                {
                    list.Add(ptr[0].Data.TrimEnd('.'));
                }

                foreach (var dom in await QueryPassiveDns(ipStr, logger))
                {
                    list.Add(dom);
                }

                var rpkiValid = await QueryRpki(ipStr, logger);

                lock (Results)
                {
                    Results.Add(new IPNeighborResult {
                        IpAddress = ipStr,
                        Domains = list.ToList(),
                        RPKIValid = rpkiValid
                    });
                }
            }
            catch (Exception ex)
            {
                lock (Errors)
                {
                    Errors.Add(ex);
                }
                logger?.WriteError("Neighbor analysis failed for {0}: {1}", ipStr, ex.Message);
            }
        });

        await Task.WhenAll(tasks);
    }
}
