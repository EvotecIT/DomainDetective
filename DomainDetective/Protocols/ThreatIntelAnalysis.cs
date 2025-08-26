using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

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
    /// <summary>Override VirusTotal query returning JSON.</summary>
    public Func<string, Task<string>>? VirusTotalOverride { private get; set; }
    /// <summary>Override VirusTotal query returning a model.</summary>
    public Func<string, Task<VirusTotalObject?>>? VirusTotalObjectOverride { private get; set; }

    /// <summary>Results returned from the consulted sources.</summary>
    public List<ThreatIntelFinding> Listings { get; } = new();
    /// <summary>Risk score returned by the reputation service.</summary>
    public int? RiskScore { get; private set; }
    /// <summary>If feed queries fail, explains why.</summary>
    public string? FailureReason { get; private set; }

    private static readonly HttpClient _staticClient = new();
    private readonly HttpClient _client;
    private VirusTotalClient? _virusTotalClient;

    internal HttpClient Client => _client;

    /// <summary>
    /// Initializes a new instance of <see cref="ThreatIntelAnalysis"/>.
    /// </summary>
    /// <param name="client">Optional HTTP client used for requests.</param>
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
        var json = JsonSerializer.Serialize(payload, JsonOptions.Default);
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

    private async Task<VirusTotalObject?> QueryVirusTotal(string domainName, string apiKey, CancellationToken ct)
    {
        if (VirusTotalObjectOverride != null)
        {
            return await VirusTotalObjectOverride(domainName);
        }

        if (VirusTotalOverride != null)
        {
            var json = await VirusTotalOverride(domainName);
            return JsonSerializer.Deserialize<VirusTotalResponse>(json, VirusTotalJson.Options)?.Data;
        }

        _virusTotalClient ??= new VirusTotalClient(apiKey);
        if (string.IsNullOrEmpty(_virusTotalClient.ApiKey))
        {
            _virusTotalClient.ApiKey = apiKey;
        }

        var isIp = System.Net.IPAddress.TryParse(domainName, out _);
        var result = isIp
            ? await _virusTotalClient.GetIpAddress(domainName, ct).ConfigureAwait(false)
            : await _virusTotalClient.GetDomain(domainName, ct).ConfigureAwait(false);
        return result?.Data;
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


    /// <summary>
    /// Queries all enabled reputation services.
    /// </summary>
    public async Task Analyze(string domainName, string? googleApiKey, string? phishTankApiKey, string? virusTotalApiKey, InternalLogger logger, CancellationToken ct = default)
    {
        Listings.Clear();
        RiskScore = null;
        FailureReason = null;

        var googleListed = false;
        var phishListed = false;
        var vtListed = false;

        if (!string.IsNullOrWhiteSpace(googleApiKey))
        {
            try
            {
                var json = await QueryGoogle(domainName, googleApiKey, ct);
                googleListed = ParseGoogle(json);
            }
            catch (Exception ex)
            {
                logger?.WriteErrorCode(ThreatIntelCodes.GsbQueryFailed, "Google Safe Browsing query failed: {0}", ex.Message);
                FailureReason = $"Google Safe Browsing query failed: {ex.Message}";
            }
        }

        if (!string.IsNullOrWhiteSpace(phishTankApiKey))
        {
            try
            {
                var json = await QueryPhishTank(domainName, phishTankApiKey, ct);
                phishListed = ParsePhishTank(json);
            }
            catch (Exception ex)
            {
                logger?.WriteErrorCode(ThreatIntelCodes.PhishTankQueryFailed, "PhishTank query failed: {0}", ex.Message);
                FailureReason = $"PhishTank query failed: {ex.Message}";
            }
        }

        if (!string.IsNullOrWhiteSpace(virusTotalApiKey))
        {
            try
            {
                var result = await QueryVirusTotal(domainName, virusTotalApiKey, ct).ConfigureAwait(false);
                vtListed = result?.Attributes?.LastAnalysisStats?.Malicious > 0;
                RiskScore = result?.Attributes?.Reputation;
                if (RiskScore.HasValue && RiskScore.Value >= 70)
                {
                    logger?.WriteWarningCode(ThreatIntelCodes.VirusTotalRiskHigh, "VirusTotal risk score {0} for {1} is high.", RiskScore.Value, domainName);
                }
            }
            catch (Exception ex)
            {
                logger?.WriteErrorCode(ThreatIntelCodes.VirusTotalQueryFailed, "VirusTotal query failed: {0}", ex.Message);
                FailureReason = $"VirusTotal query failed: {ex.Message}";
            }
        }

        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.GoogleSafeBrowsing, IsListed = googleListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.PhishTank, IsListed = phishListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.VirusTotal, IsListed = vtListed });
    }
}
