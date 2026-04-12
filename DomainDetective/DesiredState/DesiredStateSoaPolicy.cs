using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state soa policy functionality.</summary>
public sealed class DesiredStateSoaPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Gets or sets the require serial format value.</summary>
    [JsonPropertyName("requireSerialFormat")]
    public bool? RequireSerialFormat { get; set; }

    /// <summary>Gets or sets the min refresh value.</summary>
    [JsonPropertyName("minRefresh")]
    public int? MinRefresh { get; set; }

    /// <summary>Gets or sets the max refresh value.</summary>
    [JsonPropertyName("maxRefresh")]
    public int? MaxRefresh { get; set; }

    /// <summary>Gets or sets the min retry value.</summary>
    [JsonPropertyName("minRetry")]
    public int? MinRetry { get; set; }

    /// <summary>Gets or sets the max retry value.</summary>
    [JsonPropertyName("maxRetry")]
    public int? MaxRetry { get; set; }

    /// <summary>Gets or sets the min expire value.</summary>
    [JsonPropertyName("minExpire")]
    public int? MinExpire { get; set; }

    /// <summary>Gets or sets the max expire value.</summary>
    [JsonPropertyName("maxExpire")]
    public int? MaxExpire { get; set; }

    /// <summary>Gets or sets the min minimum value.</summary>
    [JsonPropertyName("minMinimum")]
    public int? MinMinimum { get; set; }

    /// <summary>Gets or sets the max minimum value.</summary>
    [JsonPropertyName("maxMinimum")]
    public int? MaxMinimum { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateSoaPolicy Clone() {
        return new DesiredStateSoaPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireSerialFormat = RequireSerialFormat,
            MinRefresh = MinRefresh,
            MaxRefresh = MaxRefresh,
            MinRetry = MinRetry,
            MaxRetry = MaxRetry,
            MinExpire = MinExpire,
            MaxExpire = MaxExpire,
            MinMinimum = MinMinimum,
            MaxMinimum = MaxMinimum
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateSoaPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireSerialFormat.HasValue) RequireSerialFormat = overlay.RequireSerialFormat;
        if (overlay.MinRefresh.HasValue) MinRefresh = overlay.MinRefresh;
        if (overlay.MaxRefresh.HasValue) MaxRefresh = overlay.MaxRefresh;
        if (overlay.MinRetry.HasValue) MinRetry = overlay.MinRetry;
        if (overlay.MaxRetry.HasValue) MaxRetry = overlay.MaxRetry;
        if (overlay.MinExpire.HasValue) MinExpire = overlay.MinExpire;
        if (overlay.MaxExpire.HasValue) MaxExpire = overlay.MaxExpire;
        if (overlay.MinMinimum.HasValue) MinMinimum = overlay.MinMinimum;
        if (overlay.MaxMinimum.HasValue) MaxMinimum = overlay.MaxMinimum;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireSerialFormat ??= false;
    }
}
