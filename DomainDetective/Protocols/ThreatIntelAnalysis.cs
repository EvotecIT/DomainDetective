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
public class ThreatIntelAnalysis : IHasAssessments
{
    public string? Subject { get; set; }
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

    /// <summary>Composite risk score (0-100) normalized across providers.</summary>
    public int? CompositeScore { get; private set; }
    /// <summary>Severity derived from <see cref="CompositeScore"/>.</summary>
    public string? Severity { get; private set; }
    /// <summary>Confidence level (0.0-1.0) based on corroborating sources.</summary>
    public double? Confidence { get; private set; }

    private static readonly HttpClient _staticClient = new();
    private readonly HttpClient _client;
    private VirusTotalClient? _virusTotalClient;
    private DateTime? _urlHausLastSeenUtc;
    private DateTime? _openPhishLastSeenUtc;
    private DateTime? _vtLastAnalysisUtc;

    internal HttpClient Client => _client;

    /// <summary>
    /// Initializes a new instance of <see cref="ThreatIntelAnalysis"/>.
    /// </summary>
    /// <param name="client">Optional HTTP client used for requests.</param>
    public ThreatIntelAnalysis(HttpClient? client = null)
    {
        _client = client ?? _staticClient;
    }

    // Provider toggles and simple in-memory caching
    public bool EnableUrlHaus { get; set; } = true;
    public bool EnableOpenPhish { get; set; } = false; // requires feed access; override supported
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(30);
    private readonly Dictionary<string, (DateTime ts, bool listed)> _cacheUrlHaus = new();
    private readonly Dictionary<string, (DateTime ts, bool listed)> _cacheOpenPhish = new();

    // Scoring weights (configurable)
    public int WeightGoogleSafeBrowsing { get; set; } = 40;
    public int WeightPhishTank { get; set; } = 25;
    public int WeightUrlHaus { get; set; } = 20;
    public int WeightOpenPhish { get; set; } = 25;
    public int WeightVirusTotalListed { get; set; } = 10;
    public int WeightVirusTotalReputation { get; set; } = 30;

    // Recency decay configuration
    public TimeSpan FreshWindow { get; set; } = TimeSpan.FromDays(7);
    public TimeSpan RecentWindow { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan MediumWindow { get; set; } = TimeSpan.FromDays(90);
    public TimeSpan StaleWindow { get; set; } = TimeSpan.FromDays(180);
    public double UnknownRecencyFactor { get; set; } = 1.0;

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
        _vtLastAnalysisUtc = null;
        var data = result?.Data;
        try { if (data?.Attributes?.LastAnalysisDateEpoch is long ts) _vtLastAnalysisUtc = DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime; } catch { }
        return data;
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

    // URLHaus host lookup (no API key required)
    private async Task<bool> QueryUrlHausListed(string domainName, CancellationToken ct)
    {
        try {
            if (_cacheUrlHaus.TryGetValue(domainName, out var e) && DateTime.UtcNow - e.ts < CacheTtl) {
                return e.listed;
            }
            using var content = new System.Net.Http.FormUrlEncodedContent(new[] { new KeyValuePair<string,string>("host", domainName) });
            using var resp = await _client.PostAsync("https://urlhaus-api.abuse.ch/v1/host/", content, ct);
            var json = await ReadAsStringAsync(resp);
            using var doc = JsonDocument.Parse(json);
            bool listed = false;
            _urlHausLastSeenUtc = null;
            if (doc.RootElement.TryGetProperty("query_status", out var status) && status.GetString() == "ok") {
                if (doc.RootElement.TryGetProperty("url_count", out var count) && count.GetInt32() > 0) listed = true;
                // Try to extract most recent timestamp from urls[] entries
                if (doc.RootElement.TryGetProperty("urls", out var urls) && urls.ValueKind == JsonValueKind.Array) {
                    DateTime? last = null;
                    foreach (var u in urls.EnumerateArray()) {
                        string? s = null;
                        if (u.TryGetProperty("last_online", out var lo) && lo.ValueKind == JsonValueKind.String) s = lo.GetString();
                        else if (u.TryGetProperty("date_added", out var da) && da.ValueKind == JsonValueKind.String) s = da.GetString();
                        if (!string.IsNullOrWhiteSpace(s) && DateTime.TryParse(s, out var dt)) {
                            if (!last.HasValue || dt.ToUniversalTime() > last.Value) last = dt.ToUniversalTime();
                        }
                    }
                    _urlHausLastSeenUtc = last;
                }
            }
            _cacheUrlHaus[domainName] = (DateTime.UtcNow, listed);
            return listed;
        } catch {
            return false;
        }
    }

    /// <summary>Override for OpenPhish JSON/CSV checks (for tests). Returns provider JSON.</summary>
    public Func<string, Task<string>>? OpenPhishOverride { private get; set; }
    private async Task<bool> QueryOpenPhishListed(string domainName, CancellationToken ct)
    {
        try {
            if (_cacheOpenPhish.TryGetValue(domainName, out var e) && DateTime.UtcNow - e.ts < CacheTtl) {
                return e.listed;
            }
            if (OpenPhishOverride != null) {
                var text = await OpenPhishOverride(domainName);
                // Expect simple responses: "listed" or JSON with { listed: true }
                bool listed = false;
                try {
                    using var doc = JsonDocument.Parse(text);
                    if (doc.RootElement.TryGetProperty("listed", out var l)) listed = l.GetBoolean();
                } catch {
                    listed = text.IndexOf("listed", StringComparison.OrdinalIgnoreCase) >= 0;
                }
                _cacheOpenPhish[domainName] = (DateTime.UtcNow, listed);
                return listed;
            }
        } catch { }
        return false; // disabled by default to avoid heavy feed downloads
    }


    /// <summary>
    /// Queries all enabled reputation services.
    /// </summary>
    public async Task Analyze(string domainName, string? googleApiKey, string? phishTankApiKey, string? virusTotalApiKey, InternalLogger logger, CancellationToken ct = default)
    {
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "THREATINTEL", target: domainName);
        Listings.Clear();
        RiskScore = null;
        FailureReason = null;
        Subject = domainName;

        var googleListed = false;
        var phishListed = false;
        var vtListed = false;
        var urlHausListed = false;
        var openPhishListed = false;

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

        // URLHaus (always attempted unless disabled)
        if (EnableUrlHaus)
        {
            try {
                urlHausListed = await QueryUrlHausListed(domainName, ct);
            } catch (Exception ex) {
                logger?.WriteErrorCode(ThreatIntelCodes.UrlHausQueryFailed, "URLHaus query failed: {0}", ex.Message);
                FailureReason = $"URLHaus query failed: {ex.Message}";
            }
        }

        // OpenPhish (disabled by default, requires override or separate feed arrangement)
        if (EnableOpenPhish)
        {
            try {
                openPhishListed = await QueryOpenPhishListed(domainName, ct);
            } catch (Exception ex) {
                logger?.WriteErrorCode(ThreatIntelCodes.OpenPhishQueryFailed, "OpenPhish query failed: {0}", ex.Message);
                FailureReason = $"OpenPhish query failed: {ex.Message}";
            }
        }

        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.GoogleSafeBrowsing, IsListed = googleListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.PhishTank, IsListed = phishListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.VirusTotal, IsListed = vtListed });
        Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.UrlHaus, IsListed = urlHausListed });
        if (EnableOpenPhish)
            Listings.Add(new ThreatIntelFinding { Source = ThreatIntelSource.OpenPhish, IsListed = openPhishListed });

        // Compute composite score and confidence
        ComputeComposite(domainName, googleListed, phishListed, vtListed, urlHausListed, openPhishListed, RiskScore);
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    private void ComputeComposite(string domain, bool gsb, bool phish, bool vt, bool urlHaus, bool openPhish, int? risk)
    {
        // Base weights per source with recency decay
        int score = 0;
        double fGsb = Factor(null); // GSB recency not exposed; treat as unknown
        double fPhish = Factor(null);
        double fUrlHaus = Factor(_urlHausLastSeenUtc);
        double fOpenPhish = Factor(_openPhishLastSeenUtc);
        double fVt = Factor(_vtLastAnalysisUtc);

        if (gsb) score += (int)System.Math.Round(WeightGoogleSafeBrowsing * fGsb);
        if (phish) score += (int)System.Math.Round(WeightPhishTank * fPhish);
        if (urlHaus) score += (int)System.Math.Round(WeightUrlHaus * fUrlHaus);
        if (openPhish) score += (int)System.Math.Round(WeightOpenPhish * fOpenPhish);
        // VirusTotal component: listing + reputation mapping (decayed)
        if (vt) score += (int)System.Math.Round(WeightVirusTotalListed * fVt); // small boost for any malicious engines
        if (risk.HasValue)
        {
            var vtComponent = (int)System.Math.Round(System.Math.Min(WeightVirusTotalReputation, System.Math.Max(0, risk.Value)) * fVt);
            score += vtComponent;
        }
        score = Math.Min(100, score);
        CompositeScore = score;

        // Severity mapping
        Severity = score >= 80 ? "Critical"
                 : score >= 60 ? "High"
                 : score >= 40 ? "Medium"
                 : score >= 20 ? "Low"
                 : "None";

        // Confidence: proportion of corroboration across sources with heuristic weights
        double conf = 0.0;
        if (gsb) conf += 0.4 * fGsb;       // high confidence
        if (phish) conf += 0.25 * fPhish;
        if (urlHaus) conf += 0.2 * fUrlHaus;
        if (openPhish) conf += 0.25 * fOpenPhish;
        if (vt && (risk ?? 0) >= 50) conf += 0.2 * fVt; // only add VT when strong
        Confidence = Math.Min(1.0, Math.Round(conf, 2));
    }

    private double Factor(DateTime? lastSeenUtc)
    {
        if (!lastSeenUtc.HasValue) return UnknownRecencyFactor;
        var age = DateTime.UtcNow - lastSeenUtc.Value;
        if (age <= FreshWindow) return 1.0;
        if (age <= RecentWindow) return 0.75;
        if (age <= MediumWindow) return 0.5;
        if (age <= StaleWindow) return 0.25;
        return 0.1;
    }
}
