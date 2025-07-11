using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Validates IP prefixes against RPKI data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class RPKIAnalysis
{
    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Override DNS queries for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Override RPKI queries for testing.</summary>
    public Func<string, Task<(string Prefix, int Asn, bool Valid)>>? QueryRpkiOverride { private get; set; }

    /// <summary>Results for each IP address.</summary>
    public List<RPKIResult> Results { get; private set; } = new();

    /// <summary>True when all IPs are valid per RPKI.</summary>
    public bool AllValid => Results.All(r => r.Valid);

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    private async Task<(string Prefix, int Asn, bool Valid)> QueryRpki(string ip, InternalLogger? logger)
    {
        if (QueryRpkiOverride != null)
        {
            return await QueryRpkiOverride(ip);
        }

        try
        {
            HttpClient client = SharedHttpClient.Instance;
            using var prefixResp = await client.GetAsync($"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}");
            prefixResp.EnsureSuccessStatusCode();
            using var prefixStream = await prefixResp.Content.ReadAsStreamAsync();
            var prefixDoc = await JsonDocument.ParseAsync(prefixStream);
            string? prefix = prefixDoc.RootElement.GetProperty("data").GetProperty("resource").GetString();
            int asn = prefixDoc.RootElement.GetProperty("data").GetProperty("asns")[0].GetProperty("asn").GetInt32();
            string rpkiUrl = $"https://stat.ripe.net/data/rpki-validation/data.json?prefix={prefix}&resource=AS{asn}";
            using var rpkiResp = await client.GetAsync(rpkiUrl);
            rpkiResp.EnsureSuccessStatusCode();
            using var rpkiStream = await rpkiResp.Content.ReadAsStreamAsync();
            var rpkiDoc = await JsonDocument.ParseAsync(rpkiStream);
            string? status = rpkiDoc.RootElement.GetProperty("data").GetProperty("status").GetString();
            bool valid = !string.Equals(status, "invalid", StringComparison.OrdinalIgnoreCase);
            return (prefix ?? string.Empty, asn, valid);
        }
        catch (Exception ex)
        {
            logger?.WriteError("RPKI query failed for {0}: {1}", ip, ex.Message);
            return (string.Empty, 0, true);
        }
    }

    /// <summary>
    /// Validates IP addresses of <paramref name="domainName"/> against RPKI repositories.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger? logger = null, CancellationToken ct = default)
    {
        Results = new List<RPKIResult>();
        var a = await QueryDns(domainName, DnsRecordType.A);
        var aaaa = await QueryDns(domainName, DnsRecordType.AAAA);

        var tasks = a.Concat(aaaa).Select(async record =>
        {
            ct.ThrowIfCancellationRequested();
            string ip = record.Data;
            var (prefix, asn, valid) = await QueryRpki(ip, logger);
            lock (Results)
            {
                Results.Add(new RPKIResult
                {
                    IpAddress = ip,
                    Prefix = prefix,
                    Asn = asn,
                    Valid = valid
                });
            }
        });

        await Task.WhenAll(tasks);
    }
}

/// <summary>Represents RPKI validation for a single IP.</summary>
/// <para>Part of the DomainDetective project.</para>
public class RPKIResult
{
    /// <summary>IP address being verified.</summary>
    public string IpAddress { get; init; } = string.Empty;
    /// <summary>Origin prefix as reported by RIPE.</summary>
    public string Prefix { get; init; } = string.Empty;
    /// <summary>Origin ASN.</summary>
    public int Asn { get; init; }
    /// <summary>Indicates whether the prefix is valid.</summary>
    public bool Valid { get; init; }
}
