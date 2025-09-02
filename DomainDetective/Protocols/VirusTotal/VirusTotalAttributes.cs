namespace DomainDetective;

using System.Text.Json.Serialization;

/// <summary>
/// Attributes for VirusTotal objects.
/// </summary>
public sealed class VirusTotalAttributes
{
    /// <summary>Last analysis statistics.</summary>
    [JsonPropertyName("last_analysis_stats")]
    public VirusTotalStats? LastAnalysisStats { get; set; }

    /// <summary>Reputation score.</summary>
    [JsonPropertyName("reputation")]
    public int? Reputation { get; set; }

    /// <summary>Unix timestamp (seconds) of last analysis.</summary>
    [JsonPropertyName("last_analysis_date")]
    public long? LastAnalysisDateEpoch { get; set; }
}
