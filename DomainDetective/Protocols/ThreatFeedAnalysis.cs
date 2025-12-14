using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Queries threat feed APIs for IP reputation data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class ThreatFeedAnalysis : IHasAssessments {
    public string? Subject { get; set; }
    /// <summary>Override VirusTotal query returning JSON.</summary>
    public Func<string, Task<string>>? VirusTotalOverride { private get; set; }
    /// <summary>Override VirusTotal query returning a model.</summary>
    public Func<string, Task<VirusTotalObject?>>? VirusTotalObjectOverride { private get; set; }
    /// <summary>Override AbuseIPDB query.</summary>
    public Func<string, Task<string>>? AbuseIpDbOverride { private get; set; }

    /// <summary>Results returned from the consulted sources.</summary>
    public List<ThreatIntelFinding> Listings { get; } = new();
    /// <summary>If feed queries fail, explains why.</summary>
    public string? FailureReason { get; private set; }

    private static readonly HttpClient _staticClient = new();
    private readonly HttpClient _client;
    private VirusTotalClient? _virusTotalClient;

    internal HttpClient Client => _client;

    /// <summary>
    /// Initializes a new instance of <see cref="ThreatFeedAnalysis"/>.
    /// </summary>
    /// <param name="client">Optional HTTP client for requests.</param>
    public ThreatFeedAnalysis(HttpClient? client = null) {
        _client = client ?? _staticClient;
    }

    private static async Task<string> ReadAsStringAsync(HttpResponseMessage resp) {
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsStringAsync();
    }

    private async Task<VirusTotalObject?> QueryVirusTotal(string ip, string apiKey, CancellationToken ct) {
        if (VirusTotalObjectOverride != null) {
            return await VirusTotalObjectOverride(ip);
        }

        if (VirusTotalOverride != null) {
            var json = await VirusTotalOverride(ip);
            return JsonSerializer.Deserialize<VirusTotalResponse>(json, VirusTotalJson.Options)?.Data;
        }

        _virusTotalClient ??= new VirusTotalClient(apiKey);
        if (string.IsNullOrEmpty(_virusTotalClient.ApiKey)) {
            _virusTotalClient.ApiKey = apiKey;
        }

        var result = await _virusTotalClient.GetIpAddress(ip, ct).ConfigureAwait(false);
        return result?.Data;
    }

    private async Task<string> QueryAbuseIpDb(string ip, string apiKey, CancellationToken ct) {
        if (AbuseIpDbOverride != null) {
            return await AbuseIpDbOverride(ip);
        }

        var url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("Key", apiKey);
        request.Headers.Add("Accept", "application/json");
        using var resp = await _client.SendAsync(request, ct);
        return await ReadAsStringAsync(resp);
    }


    private static bool ParseAbuseIpDb(string json) {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data)) {
            return false;
        }
        return data.TryGetProperty("abuseConfidenceScore", out var score) && score.GetInt32() > 0;
    }

    /// <summary>Queries all enabled threat feeds.</summary>
    public async Task Analyze(string ip, string? virusTotalApiKey, string? abuseIpDbApiKey, InternalLogger logger, CancellationToken ct = default) {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "THREATFEED", target: ip);
        Listings.Clear();
        FailureReason = null;
        Subject = ip;

        var vtListed = false;
        var abuseListed = false;

        if (virusTotalApiKey != null && !string.IsNullOrWhiteSpace(virusTotalApiKey)) {
            try {
                var result = await QueryVirusTotal(ip, virusTotalApiKey, ct).ConfigureAwait(false);
                vtListed = result?.Attributes?.LastAnalysisStats?.Malicious > 0;
            } catch (Exception ex) {
                logger?.WriteErrorCode(ThreatIntelCodes.VirusTotalQueryFailed, "VirusTotal query failed: {0}", ex.Message);
                FailureReason = $"VirusTotal query failed: {ex.Message}";
            }
        }

        if (abuseIpDbApiKey != null && !string.IsNullOrWhiteSpace(abuseIpDbApiKey)) {
            try {
                var json = await QueryAbuseIpDb(ip, abuseIpDbApiKey, ct);
                abuseListed = ParseAbuseIpDb(json);
            } catch (Exception ex) {
                logger?.WriteErrorCode(ThreatIntelCodes.AbuseIpdbQueryFailed, "AbuseIPDB query failed: {0}", ex.Message);
                FailureReason = $"AbuseIPDB query failed: {ex.Message}";
            }
        }

        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.VirusTotal, IsListed = vtListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.AbuseIpDb, IsListed = abuseListed });

        if (!vtListed && !abuseListed)
        {
            logger?.WriteInformationCode(ThreatFeedCodes.NoListings, "No threat feed providers reported malicious activity.");
        }
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
