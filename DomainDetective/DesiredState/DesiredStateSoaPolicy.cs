using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateSoaPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireSerialFormat")]
    public bool? RequireSerialFormat { get; set; }

    [JsonPropertyName("minRefresh")]
    public int? MinRefresh { get; set; }

    [JsonPropertyName("maxRefresh")]
    public int? MaxRefresh { get; set; }

    [JsonPropertyName("minRetry")]
    public int? MinRetry { get; set; }

    [JsonPropertyName("maxRetry")]
    public int? MaxRetry { get; set; }

    [JsonPropertyName("minExpire")]
    public int? MinExpire { get; set; }

    [JsonPropertyName("maxExpire")]
    public int? MaxExpire { get; set; }

    [JsonPropertyName("minMinimum")]
    public int? MinMinimum { get; set; }

    [JsonPropertyName("maxMinimum")]
    public int? MaxMinimum { get; set; }

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
