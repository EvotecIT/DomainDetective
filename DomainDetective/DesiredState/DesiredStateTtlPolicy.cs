using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateTtlPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("minASeconds")]
    public int? MinASeconds { get; set; }

    [JsonPropertyName("maxASeconds")]
    public int? MaxASeconds { get; set; }

    [JsonPropertyName("minAaaaSeconds")]
    public int? MinAaaaSeconds { get; set; }

    [JsonPropertyName("maxAaaaSeconds")]
    public int? MaxAaaaSeconds { get; set; }

    [JsonPropertyName("minMxSeconds")]
    public int? MinMxSeconds { get; set; }

    [JsonPropertyName("maxMxSeconds")]
    public int? MaxMxSeconds { get; set; }

    [JsonPropertyName("minNsSeconds")]
    public int? MinNsSeconds { get; set; }

    [JsonPropertyName("maxNsSeconds")]
    public int? MaxNsSeconds { get; set; }

    [JsonPropertyName("minSoaSeconds")]
    public int? MinSoaSeconds { get; set; }

    [JsonPropertyName("maxSoaSeconds")]
    public int? MaxSoaSeconds { get; set; }

    [JsonPropertyName("minSpfTxtSeconds")]
    public int? MinSpfTxtSeconds { get; set; }

    [JsonPropertyName("maxSpfTxtSeconds")]
    public int? MaxSpfTxtSeconds { get; set; }

    [JsonPropertyName("minDmarcTxtSeconds")]
    public int? MinDmarcTxtSeconds { get; set; }

    [JsonPropertyName("maxDmarcTxtSeconds")]
    public int? MaxDmarcTxtSeconds { get; set; }

    [JsonPropertyName("minDkimSelectorTxtSeconds")]
    public int? MinDkimSelectorTxtSeconds { get; set; }

    [JsonPropertyName("maxDkimSelectorTxtSeconds")]
    public int? MaxDkimSelectorTxtSeconds { get; set; }

    [JsonPropertyName("minMtastsTxtSeconds")]
    public int? MinMtastsTxtSeconds { get; set; }

    [JsonPropertyName("maxMtastsTxtSeconds")]
    public int? MaxMtastsTxtSeconds { get; set; }

    [JsonPropertyName("minTlsRptTxtSeconds")]
    public int? MinTlsRptTxtSeconds { get; set; }

    [JsonPropertyName("maxTlsRptTxtSeconds")]
    public int? MaxTlsRptTxtSeconds { get; set; }

    [JsonPropertyName("requireAUniformAcrossNs")]
    public bool? RequireAUniformAcrossNs { get; set; }

    [JsonPropertyName("requireAaaaUniformAcrossNs")]
    public bool? RequireAaaaUniformAcrossNs { get; set; }

    [JsonPropertyName("requireNsUniformAcrossNs")]
    public bool? RequireNsUniformAcrossNs { get; set; }

    [JsonPropertyName("requireCnameUniformAcrossNs")]
    public bool? RequireCnameUniformAcrossNs { get; set; }

    [JsonPropertyName("requireSpfTxtUniformAcrossNs")]
    public bool? RequireSpfTxtUniformAcrossNs { get; set; }

    [JsonPropertyName("requireDmarcTxtUniformAcrossNs")]
    public bool? RequireDmarcTxtUniformAcrossNs { get; set; }

    [JsonPropertyName("requireMtastsTxtUniformAcrossNs")]
    public bool? RequireMtastsTxtUniformAcrossNs { get; set; }

    [JsonPropertyName("requireTlsRptTxtUniformAcrossNs")]
    public bool? RequireTlsRptTxtUniformAcrossNs { get; set; }

    [JsonPropertyName("requireDkimTxtUniformAcrossNs")]
    public bool? RequireDkimTxtUniformAcrossNs { get; set; }

    public DesiredStateTtlPolicy Clone() {
        return new DesiredStateTtlPolicy {
            Enabled = Enabled,
            MinASeconds = MinASeconds,
            MaxASeconds = MaxASeconds,
            MinAaaaSeconds = MinAaaaSeconds,
            MaxAaaaSeconds = MaxAaaaSeconds,
            MinMxSeconds = MinMxSeconds,
            MaxMxSeconds = MaxMxSeconds,
            MinNsSeconds = MinNsSeconds,
            MaxNsSeconds = MaxNsSeconds,
            MinSoaSeconds = MinSoaSeconds,
            MaxSoaSeconds = MaxSoaSeconds,
            MinSpfTxtSeconds = MinSpfTxtSeconds,
            MaxSpfTxtSeconds = MaxSpfTxtSeconds,
            MinDmarcTxtSeconds = MinDmarcTxtSeconds,
            MaxDmarcTxtSeconds = MaxDmarcTxtSeconds,
            MinDkimSelectorTxtSeconds = MinDkimSelectorTxtSeconds,
            MaxDkimSelectorTxtSeconds = MaxDkimSelectorTxtSeconds,
            MinMtastsTxtSeconds = MinMtastsTxtSeconds,
            MaxMtastsTxtSeconds = MaxMtastsTxtSeconds,
            MinTlsRptTxtSeconds = MinTlsRptTxtSeconds,
            MaxTlsRptTxtSeconds = MaxTlsRptTxtSeconds,
            RequireAUniformAcrossNs = RequireAUniformAcrossNs,
            RequireAaaaUniformAcrossNs = RequireAaaaUniformAcrossNs,
            RequireNsUniformAcrossNs = RequireNsUniformAcrossNs,
            RequireCnameUniformAcrossNs = RequireCnameUniformAcrossNs,
            RequireSpfTxtUniformAcrossNs = RequireSpfTxtUniformAcrossNs,
            RequireDmarcTxtUniformAcrossNs = RequireDmarcTxtUniformAcrossNs,
            RequireMtastsTxtUniformAcrossNs = RequireMtastsTxtUniformAcrossNs,
            RequireTlsRptTxtUniformAcrossNs = RequireTlsRptTxtUniformAcrossNs,
            RequireDkimTxtUniformAcrossNs = RequireDkimTxtUniformAcrossNs
        };
    }

    public void Apply(DesiredStateTtlPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.MinASeconds.HasValue) MinASeconds = overlay.MinASeconds;
        if (overlay.MaxASeconds.HasValue) MaxASeconds = overlay.MaxASeconds;
        if (overlay.MinAaaaSeconds.HasValue) MinAaaaSeconds = overlay.MinAaaaSeconds;
        if (overlay.MaxAaaaSeconds.HasValue) MaxAaaaSeconds = overlay.MaxAaaaSeconds;
        if (overlay.MinMxSeconds.HasValue) MinMxSeconds = overlay.MinMxSeconds;
        if (overlay.MaxMxSeconds.HasValue) MaxMxSeconds = overlay.MaxMxSeconds;
        if (overlay.MinNsSeconds.HasValue) MinNsSeconds = overlay.MinNsSeconds;
        if (overlay.MaxNsSeconds.HasValue) MaxNsSeconds = overlay.MaxNsSeconds;
        if (overlay.MinSoaSeconds.HasValue) MinSoaSeconds = overlay.MinSoaSeconds;
        if (overlay.MaxSoaSeconds.HasValue) MaxSoaSeconds = overlay.MaxSoaSeconds;
        if (overlay.MinSpfTxtSeconds.HasValue) MinSpfTxtSeconds = overlay.MinSpfTxtSeconds;
        if (overlay.MaxSpfTxtSeconds.HasValue) MaxSpfTxtSeconds = overlay.MaxSpfTxtSeconds;
        if (overlay.MinDmarcTxtSeconds.HasValue) MinDmarcTxtSeconds = overlay.MinDmarcTxtSeconds;
        if (overlay.MaxDmarcTxtSeconds.HasValue) MaxDmarcTxtSeconds = overlay.MaxDmarcTxtSeconds;
        if (overlay.MinDkimSelectorTxtSeconds.HasValue) MinDkimSelectorTxtSeconds = overlay.MinDkimSelectorTxtSeconds;
        if (overlay.MaxDkimSelectorTxtSeconds.HasValue) MaxDkimSelectorTxtSeconds = overlay.MaxDkimSelectorTxtSeconds;
        if (overlay.MinMtastsTxtSeconds.HasValue) MinMtastsTxtSeconds = overlay.MinMtastsTxtSeconds;
        if (overlay.MaxMtastsTxtSeconds.HasValue) MaxMtastsTxtSeconds = overlay.MaxMtastsTxtSeconds;
        if (overlay.MinTlsRptTxtSeconds.HasValue) MinTlsRptTxtSeconds = overlay.MinTlsRptTxtSeconds;
        if (overlay.MaxTlsRptTxtSeconds.HasValue) MaxTlsRptTxtSeconds = overlay.MaxTlsRptTxtSeconds;
        if (overlay.RequireAUniformAcrossNs.HasValue) RequireAUniformAcrossNs = overlay.RequireAUniformAcrossNs;
        if (overlay.RequireAaaaUniformAcrossNs.HasValue) RequireAaaaUniformAcrossNs = overlay.RequireAaaaUniformAcrossNs;
        if (overlay.RequireNsUniformAcrossNs.HasValue) RequireNsUniformAcrossNs = overlay.RequireNsUniformAcrossNs;
        if (overlay.RequireCnameUniformAcrossNs.HasValue) RequireCnameUniformAcrossNs = overlay.RequireCnameUniformAcrossNs;
        if (overlay.RequireSpfTxtUniformAcrossNs.HasValue) RequireSpfTxtUniformAcrossNs = overlay.RequireSpfTxtUniformAcrossNs;
        if (overlay.RequireDmarcTxtUniformAcrossNs.HasValue) RequireDmarcTxtUniformAcrossNs = overlay.RequireDmarcTxtUniformAcrossNs;
        if (overlay.RequireMtastsTxtUniformAcrossNs.HasValue) RequireMtastsTxtUniformAcrossNs = overlay.RequireMtastsTxtUniformAcrossNs;
        if (overlay.RequireTlsRptTxtUniformAcrossNs.HasValue) RequireTlsRptTxtUniformAcrossNs = overlay.RequireTlsRptTxtUniformAcrossNs;
        if (overlay.RequireDkimTxtUniformAcrossNs.HasValue) RequireDkimTxtUniformAcrossNs = overlay.RequireDkimTxtUniformAcrossNs;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAUniformAcrossNs ??= false;
        RequireAaaaUniformAcrossNs ??= false;
        RequireNsUniformAcrossNs ??= false;
        RequireCnameUniformAcrossNs ??= false;
        RequireSpfTxtUniformAcrossNs ??= false;
        RequireDmarcTxtUniformAcrossNs ??= false;
        RequireMtastsTxtUniformAcrossNs ??= false;
        RequireTlsRptTxtUniformAcrossNs ??= false;
        RequireDkimTxtUniformAcrossNs ??= false;
    }
}
