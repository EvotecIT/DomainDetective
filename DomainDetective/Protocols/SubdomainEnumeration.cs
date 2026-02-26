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
/// Enumerates subdomains using dictionary brute force and passive sources.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class SubdomainEnumeration
{
    /// <summary>DNS configuration for queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Subdomain wordlist used for brute force.</summary>
    public List<string> Dictionary { get; } = new() { "www", "mail", "ftp", "dev", "test" };

    /// <summary>Override DNS query logic for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
    /// <summary>Override passive enumeration logic for testing.</summary>
    public Func<string, CancellationToken, Task<IEnumerable<string>>>? PassiveLookupOverride { private get; set; }
    /// <summary>Override passive HTTP fetch logic for testing.</summary>
    internal Func<string, CancellationToken, Task<string>>? PassiveHttpGetOverride { private get; set; }

    /// <summary>URL template for crt.sh lookups.</summary>
    public string CrtShUrlTemplate { get; set; } = "https://crt.sh/?q=%25.{0}&output=json";

    /// <summary>Fallback URL template for Cert Spotter lookups.</summary>
    public string CertSpotterUrlTemplate { get; set; } = "https://api.certspotter.com/v1/issuances?domain={0}&include_subdomains=true&expand=dns_names";

    /// <summary>When true (default), tries Cert Spotter if crt.sh fails.</summary>
    public bool UseCertSpotterFallback { get; set; } = true;

    /// <summary>List of subdomains discovered via brute force.</summary>
    public List<string> BruteForceResults { get; private set; } = new();

    /// <summary>List of subdomains discovered via passive sources.</summary>
    public List<string> PassiveResults { get; private set; } = new();

    private static readonly HttpClient _client = new();

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type);
    }

    private async Task<IEnumerable<string>> QueryPassive(string domain, CancellationToken ct)
    {
        if (PassiveLookupOverride != null)
        {
            return await PassiveLookupOverride(domain, ct);
        }

        string? failure = null;
        if (!string.IsNullOrWhiteSpace(CrtShUrlTemplate))
        {
            try
            {
                return await QueryPassiveFromUrl(string.Format(CrtShUrlTemplate, domain), ct);
            }
            catch (Exception ex)
            {
                failure = ex.Message;
            }
        }

        if (UseCertSpotterFallback && !string.IsNullOrWhiteSpace(CertSpotterUrlTemplate))
        {
            try
            {
                return await QueryPassiveFromUrl(string.Format(CertSpotterUrlTemplate, Uri.EscapeDataString(domain)), ct);
            }
            catch (Exception ex)
            {
                failure = failure == null ? ex.Message : $"{failure}; fallback failed: {ex.Message}";
            }
        }

        throw new InvalidOperationException(failure ?? "No passive CT source succeeded.");
    }

    private static string? GetString(JsonElement obj, string propertyName)
    {
        if (obj.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!obj.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private async Task<IEnumerable<string>> QueryPassiveFromUrl(string url, CancellationToken ct)
    {
        string json;
        if (PassiveHttpGetOverride != null)
        {
            json = await PassiveHttpGetOverride(url, ct);
        }
        else
        {
            using var resp = await _client.GetAsync(url, ct);
            resp.EnsureSuccessStatusCode();
            json = await resp.Content.ReadAsStringAsync();
        }

        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var list = new List<string>();
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            var namesRaw = GetString(item, "name_value");
            if (!string.IsNullOrWhiteSpace(namesRaw))
            {
                list.AddRange(namesRaw!.Split('\n'));
            }

            if (item.ValueKind == JsonValueKind.Object &&
                item.TryGetProperty("dns_names", out var dnsNames) &&
                dnsNames.ValueKind == JsonValueKind.Array)
            {
                foreach (var dnsName in dnsNames.EnumerateArray())
                {
                    if (dnsName.ValueKind == JsonValueKind.String)
                    {
                        var value = dnsName.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            list.Add(value!);
                        }
                    }
                }
            }
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Performs enumeration for <paramref name="domain"/>.
    /// </summary>
    public async Task Enumerate(string domain, InternalLogger logger, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentNullException(nameof(domain));
        }

        BruteForceResults = new List<string>();
        PassiveResults = new List<string>();

        foreach (var word in Dictionary)
        {
            ct.ThrowIfCancellationRequested();
            var name = $"{word}.{domain}";
            var a = await QueryDns(name, DnsRecordType.A);
            var aaaa = await QueryDns(name, DnsRecordType.AAAA);
            if ((a?.Length > 0) || (aaaa?.Length > 0))
            {
                BruteForceResults.Add(name);
                logger?.WriteVerbose("Found subdomain: {0}", name);
            }
        }

        try
        {
            var passive = await QueryPassive(domain, ct);
            PassiveResults = passive.ToList();
        }
        catch (Exception ex)
        {
            logger?.WriteErrorCode(SubdomainCodes.PassiveQueryFailed, "Passive enumeration failed: {0}", ex.Message);
        }
    }
}
