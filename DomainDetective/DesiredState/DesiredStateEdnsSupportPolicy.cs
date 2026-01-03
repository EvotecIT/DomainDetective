using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateEdnsSupportPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no EDNS results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, requires all authoritative server endpoints to support EDNS.</summary>
    [JsonPropertyName("requireAllServersSupported")]
    public bool? RequireAllServersSupported { get; set; }

    /// <summary>Optional maximum EDNS UDP payload size (bytes) that servers are allowed to advertise.</summary>
    [JsonPropertyName("maxUdpPayloadSize")]
    public int? MaxUdpPayloadSize { get; set; }

    /// <summary>When true, requires EDNS version 0.</summary>
    [JsonPropertyName("requireVersionZero")]
    public bool? RequireVersionZero { get; set; }

    /// <summary>When true, requires authoritative servers to support DNS Cookies (RFC 7873).</summary>
    [JsonPropertyName("requireCookieSupport")]
    public bool? RequireCookieSupport { get; set; }

    public DesiredStateEdnsSupportPolicy Clone() {
        return new DesiredStateEdnsSupportPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireAllServersSupported = RequireAllServersSupported,
            MaxUdpPayloadSize = MaxUdpPayloadSize,
            RequireVersionZero = RequireVersionZero,
            RequireCookieSupport = RequireCookieSupport
        };
    }

    public void Apply(DesiredStateEdnsSupportPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireAllServersSupported.HasValue) RequireAllServersSupported = overlay.RequireAllServersSupported;
        if (overlay.MaxUdpPayloadSize.HasValue) MaxUdpPayloadSize = overlay.MaxUdpPayloadSize;
        if (overlay.RequireVersionZero.HasValue) RequireVersionZero = overlay.RequireVersionZero;
        if (overlay.RequireCookieSupport.HasValue) RequireCookieSupport = overlay.RequireCookieSupport;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireAllServersSupported ??= true;
        RequireVersionZero ??= true;
        RequireCookieSupport ??= false;
    }
}

