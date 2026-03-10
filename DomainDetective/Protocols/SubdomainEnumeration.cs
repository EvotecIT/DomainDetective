using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
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

    /// <summary>Per-request timeout for passive/public CT HTTP calls.</summary>
    public TimeSpan PassiveCtRequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum retry count for transient passive/public CT HTTP failures.</summary>
    public int PassiveCtRetryCount { get; set; } = 2;

    /// <summary>Base delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(750);

    /// <summary>Maximum delay between passive/public CT retry attempts.</summary>
    public TimeSpan PassiveCtRetryMaxDelay { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Cooldown applied to passive/public CT sources after transient failures or rate limits.</summary>
    public TimeSpan PassiveCtSourceCooldown { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>List of subdomains discovered via brute force.</summary>
    public List<string> BruteForceResults { get; private set; } = new();

    /// <summary>List of subdomains discovered via passive sources.</summary>
    public List<string> PassiveResults { get; private set; } = new();

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

        var requests = new List<PassiveCtSourceClient.SourceRequest>(2);
        if (!string.IsNullOrWhiteSpace(CrtShUrlTemplate))
        {
            requests.Add(new PassiveCtSourceClient.SourceRequest
            {
                SourceName = "crt.sh",
                Url = string.Format(CrtShUrlTemplate, domain)
            });
        }

        if (UseCertSpotterFallback && !string.IsNullOrWhiteSpace(CertSpotterUrlTemplate))
        {
            requests.Add(new PassiveCtSourceClient.SourceRequest
            {
                SourceName = "certspotter",
                Url = string.Format(CertSpotterUrlTemplate, Uri.EscapeDataString(domain))
            });
        }

        var client = new PassiveCtSourceClient();
        PassiveCtSourceClient.QueryResult result = await client.QueryAsync(
            requests,
            new PassiveCtSourceClient.QueryOptions
            {
                RequestTimeout = PassiveCtRequestTimeout,
                RetryCount = PassiveCtRetryCount,
                RetryBaseDelay = PassiveCtRetryBaseDelay,
                RetryMaxDelay = PassiveCtRetryMaxDelay,
                SourceCooldown = PassiveCtSourceCooldown,
                PayloadValidator = ValidatePassiveCtArrayPayload
            },
            PassiveHttpGetOverride,
            logger: null,
            ct).ConfigureAwait(false);
        if (result.Payloads.Count == 0)
        {
            throw new InvalidOperationException(
                result.Warnings.Count > 0
                    ? string.Join("; ", result.Warnings)
                    : "No passive CT source succeeded.");
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (PassiveCtSourceClient.SourcePayload payload in result.Payloads)
        {
            foreach (string name in ParsePassiveNames(payload.Payload))
            {
                names.Add(name);
            }
        }

        return names;
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

    private static IEnumerable<string> ParsePassiveNames(string json)
    {
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

    private static string? ValidatePassiveCtArrayPayload(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return "response payload was empty.";
        }

        try
        {
            using var document = JsonDocument.Parse(payload);
            return document.RootElement.ValueKind == JsonValueKind.Array
                ? null
                : "response root element must be an array.";
        }
        catch (JsonException ex)
        {
            return ex.Message;
        }
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
