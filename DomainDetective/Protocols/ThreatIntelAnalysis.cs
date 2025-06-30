using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries threat intelligence services for reputation data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class ThreatIntelAnalysis
{
    /// <summary>Override Safe Browsing query.</summary>
    public Func<string, Task<string>>? GoogleSafeBrowsingOverride { private get; set; }
    /// <summary>Override PhishTank query.</summary>
    public Func<string, Task<string>>? PhishTankOverride { private get; set; }
    /// <summary>Override VirusTotal query.</summary>
    public Func<string, Task<string>>? VirusTotalOverride { private get; set; }

    /// <summary>True when Google Safe Browsing lists the entry.</summary>
    public bool ListedByGoogle { get; private set; }
    /// <summary>True when PhishTank lists the entry.</summary>
    public bool ListedByPhishTank { get; private set; }
    /// <summary>True when VirusTotal lists the entry as malicious.</summary>
    public bool ListedByVirusTotal { get; private set; }
    /// <summary>If feed queries fail, explains why.</summary>
    public string? FailureReason { get; private set; }

    private static readonly HttpClient _staticClient = new();
    private readonly HttpClient _client;

    internal HttpClient Client => _client;

    public ThreatIntelAnalysis(HttpClient? client = null)
    {
        _client = client ?? _staticClient;
    }

    private static async Task<string> ReadAsStringAsync(HttpResponseMessage resp)
    {
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync();
    }

    private async Task<string> QueryGoogle(string domainName, string apiKey, CancellationToken ct)
    {
        if (GoogleSafeBrowsingOverride != null)
        {
            return await GoogleSafeBrowsingOverride(domainName);
        }

        var url = $"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={apiKey}";
        var payload = new
        {
            client = new { clientId = "domain-detective", clientVersion = "1.0" },
            threatInfo = new
            {
                threatTypes = new[] { "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION" },
                platformTypes = new[] { "ANY_PLATFORM" },
                threatEntryTypes = new[] { "URL" },
                threatEntries = new[] { new { url = domainName } }
            }
        };
        var json = JsonSerializer.Serialize(payload);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await _client.PostAsync(url, content, ct);
        return await ReadAsStringAsync(resp);
    }

    private async Task<string> QueryPhishTank(string domainName, string apiKey, CancellationToken ct)
    {
        if (PhishTankOverride != null)
        {
            return await PhishTankOverride(domainName);
        }

        var url = $"https://checkurl.phishtank.com/checkurl/?format=json&app_key={apiKey}&url={Uri.EscapeDataString(domainName)}";
        using var resp = await _client.GetAsync(url, ct);
        return await ReadAsStringAsync(resp);
    }

    private async Task<string> QueryVirusTotal(string domainName, string apiKey, CancellationToken ct)
    {
        if (VirusTotalOverride != null)
        {
            return await VirusTotalOverride(domainName);
        }

        var isIp = System.Net.IPAddress.TryParse(domainName, out _);
        var url = isIp
            ? $"https://www.virustotal.com/api/v3/ip_addresses/{domainName}"
            : $"https://www.virustotal.com/api/v3/domains/{domainName}";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("x-apikey", apiKey);
        using var resp = await _client.SendAsync(request, ct);
        return await ReadAsStringAsync(resp);
    }

    private static bool ParseGoogle(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("matches", out var m) && m.GetArrayLength() > 0;
    }

    private static bool ParsePhishTank(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("results", out var res))
        {
            return false;
        }
        var valid = res.TryGetProperty("valid", out var v) && v.GetString() == "true";
        var inDb = res.TryGetProperty("in_database", out var db) && db.GetString() == "true";
        return valid && inDb;
    }

    private static bool ParseVirusTotal(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data))
        {
            return false;
        }
        if (!data.TryGetProperty("attributes", out var attr))
        {
            return false;
        }
        if (!attr.TryGetProperty("last_analysis_stats", out var stats))
        {
            return false;
        }
        return stats.TryGetProperty("malicious", out var mal) && mal.GetInt32() > 0;
    }

    /// <summary>
    /// Queries all enabled reputation services.
    /// </summary>
    public async Task Analyze(string domainName, string? googleApiKey, string? phishTankApiKey, string? virusTotalApiKey, InternalLogger logger, CancellationToken ct = default)
    {
        ListedByGoogle = false;
        ListedByPhishTank = false;
        ListedByVirusTotal = false;
        FailureReason = null;

        if (!string.IsNullOrWhiteSpace(googleApiKey))
        {
            try
            {
                var json = await QueryGoogle(domainName, googleApiKey, ct);
                ListedByGoogle = ParseGoogle(json);
            }
            catch (Exception ex)
            {
                logger?.WriteError("Google Safe Browsing query failed: {0}", ex.Message);
                FailureReason = $"Google Safe Browsing query failed: {ex.Message}";
            }
        }

        if (!string.IsNullOrWhiteSpace(phishTankApiKey))
        {
            try
            {
                var json = await QueryPhishTank(domainName, phishTankApiKey, ct);
                ListedByPhishTank = ParsePhishTank(json);
            }
            catch (Exception ex)
            {
                logger?.WriteError("PhishTank query failed: {0}", ex.Message);
                FailureReason = $"PhishTank query failed: {ex.Message}";
            }
        }

        if (!string.IsNullOrWhiteSpace(virusTotalApiKey))
        {
            try
            {
                var json = await QueryVirusTotal(domainName, virusTotalApiKey, ct);
                ListedByVirusTotal = ParseVirusTotal(json);
            }
            catch (Exception ex)
            {
                logger?.WriteError("VirusTotal query failed: {0}", ex.Message);
                FailureReason = $"VirusTotal query failed: {ex.Message}";
            }
        }
    }
}
