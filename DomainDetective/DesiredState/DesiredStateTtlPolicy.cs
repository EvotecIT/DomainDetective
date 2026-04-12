using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state ttl policy functionality.</summary>
public sealed class DesiredStateTtlPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the min a seconds value.</summary>
    [JsonPropertyName("minASeconds")]
    public int? MinASeconds { get; set; }

    /// <summary>Gets or sets the max a seconds value.</summary>
    [JsonPropertyName("maxASeconds")]
    public int? MaxASeconds { get; set; }

    /// <summary>Gets or sets the min aaaa seconds value.</summary>
    [JsonPropertyName("minAaaaSeconds")]
    public int? MinAaaaSeconds { get; set; }

    /// <summary>Gets or sets the max aaaa seconds value.</summary>
    [JsonPropertyName("maxAaaaSeconds")]
    public int? MaxAaaaSeconds { get; set; }

    /// <summary>Gets or sets the min mx seconds value.</summary>
    [JsonPropertyName("minMxSeconds")]
    public int? MinMxSeconds { get; set; }

    /// <summary>Gets or sets the max mx seconds value.</summary>
    [JsonPropertyName("maxMxSeconds")]
    public int? MaxMxSeconds { get; set; }

    /// <summary>Gets or sets the min ns seconds value.</summary>
    [JsonPropertyName("minNsSeconds")]
    public int? MinNsSeconds { get; set; }

    /// <summary>Gets or sets the max ns seconds value.</summary>
    [JsonPropertyName("maxNsSeconds")]
    public int? MaxNsSeconds { get; set; }

    /// <summary>Gets or sets the min soa seconds value.</summary>
    [JsonPropertyName("minSoaSeconds")]
    public int? MinSoaSeconds { get; set; }

    /// <summary>Gets or sets the max soa seconds value.</summary>
    [JsonPropertyName("maxSoaSeconds")]
    public int? MaxSoaSeconds { get; set; }

    /// <summary>Gets or sets the min spf txt seconds value.</summary>
    [JsonPropertyName("minSpfTxtSeconds")]
    public int? MinSpfTxtSeconds { get; set; }

    /// <summary>Gets or sets the max spf txt seconds value.</summary>
    [JsonPropertyName("maxSpfTxtSeconds")]
    public int? MaxSpfTxtSeconds { get; set; }

    /// <summary>Gets or sets the min dmarc txt seconds value.</summary>
    [JsonPropertyName("minDmarcTxtSeconds")]
    public int? MinDmarcTxtSeconds { get; set; }

    /// <summary>Gets or sets the max dmarc txt seconds value.</summary>
    [JsonPropertyName("maxDmarcTxtSeconds")]
    public int? MaxDmarcTxtSeconds { get; set; }

    /// <summary>Gets or sets the min dkim selector txt seconds value.</summary>
    [JsonPropertyName("minDkimSelectorTxtSeconds")]
    public int? MinDkimSelectorTxtSeconds { get; set; }

    /// <summary>Gets or sets the max dkim selector txt seconds value.</summary>
    [JsonPropertyName("maxDkimSelectorTxtSeconds")]
    public int? MaxDkimSelectorTxtSeconds { get; set; }

    /// <summary>Gets or sets the min mtasts txt seconds value.</summary>
    [JsonPropertyName("minMtastsTxtSeconds")]
    public int? MinMtastsTxtSeconds { get; set; }

    /// <summary>Gets or sets the max mtasts txt seconds value.</summary>
    [JsonPropertyName("maxMtastsTxtSeconds")]
    public int? MaxMtastsTxtSeconds { get; set; }

    /// <summary>Gets or sets the min tls rpt txt seconds value.</summary>
    [JsonPropertyName("minTlsRptTxtSeconds")]
    public int? MinTlsRptTxtSeconds { get; set; }

    /// <summary>Gets or sets the max tls rpt txt seconds value.</summary>
    [JsonPropertyName("maxTlsRptTxtSeconds")]
    public int? MaxTlsRptTxtSeconds { get; set; }

    /// <summary>Gets or sets the require a uniform across ns value.</summary>
    [JsonPropertyName("requireAUniformAcrossNs")]
    public bool? RequireAUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require aaaa uniform across ns value.</summary>
    [JsonPropertyName("requireAaaaUniformAcrossNs")]
    public bool? RequireAaaaUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require ns uniform across ns value.</summary>
    [JsonPropertyName("requireNsUniformAcrossNs")]
    public bool? RequireNsUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require cname uniform across ns value.</summary>
    [JsonPropertyName("requireCnameUniformAcrossNs")]
    public bool? RequireCnameUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require spf txt uniform across ns value.</summary>
    [JsonPropertyName("requireSpfTxtUniformAcrossNs")]
    public bool? RequireSpfTxtUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require dmarc txt uniform across ns value.</summary>
    [JsonPropertyName("requireDmarcTxtUniformAcrossNs")]
    public bool? RequireDmarcTxtUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require mtasts txt uniform across ns value.</summary>
    [JsonPropertyName("requireMtastsTxtUniformAcrossNs")]
    public bool? RequireMtastsTxtUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require tls rpt txt uniform across ns value.</summary>
    [JsonPropertyName("requireTlsRptTxtUniformAcrossNs")]
    public bool? RequireTlsRptTxtUniformAcrossNs { get; set; }

    /// <summary>Gets or sets the require dkim txt uniform across ns value.</summary>
    [JsonPropertyName("requireDkimTxtUniformAcrossNs")]
    public bool? RequireDkimTxtUniformAcrossNs { get; set; }

    /// <summary>Executes the clone operation.</summary>
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

    /// <summary>Executes the apply operation.</summary>
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
