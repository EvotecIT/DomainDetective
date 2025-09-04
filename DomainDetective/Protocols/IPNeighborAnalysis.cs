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
public class IPNeighborAnalysis : IHasAssessments
{
    /// <summary>Subject of the check (domain name).</summary>
    public string? Subject { get; set; }
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

    public List<Assessment> Assessments { get; } = new();
    /// <summary>TTL for passive DNS cache entries.</summary>
    public TimeSpan PassiveDnsCacheTtl { get; set; } = TimeSpan.FromMinutes(30);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime ts, List<string> list)> _passiveDnsCache = new();

    private static string Categorize(int count)
    {
        if (count >= 200) return "Extreme";
        if (count >= 50) return "High";
        if (count >= 10) return "Medium";
        return "Low";
    }

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

        if (_passiveDnsCache.TryGetValue(ip, out var cached) && DateTime.UtcNow - cached.ts < PassiveDnsCacheTtl)
        {
            return cached.list;
        }

        try
        {
            var client = SharedHttpClient.Instance;
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
            _passiveDnsCache[ip] = (DateTime.UtcNow, domains);
            return domains;
        }
        catch (Exception ex)
        {
            logger?.WriteErrorCode(IpNeighborCodes.PassiveDnsQueryFailed, "Passive DNS query failed for {0}: {1}", ip, ex.Message);
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
            var client = SharedHttpClient.Instance;
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
            logger?.WriteErrorCode(RpkiCodes.QueryFailed, "RPKI query failed for {0}: {1}", ip, ex.Message);
            return true;
        }
    }

    /// <summary>
    /// Queries PTR and passive DNS for all IPs of <paramref name="domainName"/>.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        Subject = domainName;
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
                        RPKIValid = rpkiValid,
                        CoHostCount = list.Count,
                        Category = Categorize(list.Count),
                        Type = "Apex"
                    });
                }
                // Emit assessment if excessive number of co-hosted domains
                if (list.Count > 50)
                {
                    using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "IPNeighbor", target: ipStr) : null;
                    logger?.WriteWarningCode(IpNeighborCodes.ExcessiveCoHosts, "{0} co-hosted domains observed on {1}", list.Count, ipStr);
                }
            }
            catch (Exception ex)
            {
                lock (Errors)
                {
                    Errors.Add(ex);
                }
                logger?.WriteErrorCode(IpNeighborCodes.AnalysisFailed, "Neighbor analysis failed for {0}: {1}", ipStr, ex.Message);
            }
        });

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Enumerates neighbors for IPs used by MX targets of the domain.
    /// </summary>
    public async Task AnalyzeMx(string domainName, InternalLogger logger, CancellationToken ct = default)
    {
        Subject = domainName;
        var mxRecords = await QueryDns(domainName, DnsRecordType.MX);
        var mxHosts = CertificateAnalysis.ExtractMxHosts(mxRecords);
        foreach (var host in mxHosts)
        {
            ct.ThrowIfCancellationRequested();
            var a = await QueryDns(host, DnsRecordType.A);
            var aaaa = await QueryDns(host, DnsRecordType.AAAA);
            foreach (var record in a.Concat(aaaa))
            {
                if (!IPAddress.TryParse(record.Data, out var ip)) continue;
                var ipStr = ip.ToString();
                var list = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    foreach (var dom in await QueryPassiveDns(ipStr, logger)) list.Add(dom);
                    var rpkiValid = await QueryRpki(ipStr, logger);
                    lock (Results)
                    {
                        Results.Add(new IPNeighborResult {
                            IpAddress = ipStr,
                            Domains = list.ToList(),
                            RPKIValid = rpkiValid,
                            CoHostCount = list.Count,
                            Category = Categorize(list.Count),
                            Type = "MX"
                        });
                    }
                    if (list.Count > 50)
                    {
                        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "IPNeighbor", target: ipStr) : null;
                        logger?.WriteWarningCode(IpNeighborCodes.MailOnSharedIp, "MX IP {0} hosts {1} domains", ipStr, list.Count);
                    }
                }
                catch (Exception ex)
                {
                    lock (Errors) { Errors.Add(ex); }
                    logger?.WriteErrorCode(IpNeighborCodes.AnalysisFailed, "Neighbor analysis failed for MX IP {0}: {1}", ipStr, ex.Message);
                }
            }
        }
    }
}
