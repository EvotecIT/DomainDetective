using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state autodiscover policy functionality.</summary>
public sealed class DesiredStateAutodiscoverPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require srv record value.</summary>
    [JsonPropertyName("requireSrvRecord")]
    public bool? RequireSrvRecord { get; set; }

    /// <summary>Gets or sets the require autodiscover cname value.</summary>
    [JsonPropertyName("requireAutodiscoverCname")]
    public bool? RequireAutodiscoverCname { get; set; }

    /// <summary>Gets or sets the require autoconfig cname value.</summary>
    [JsonPropertyName("requireAutoconfigCname")]
    public bool? RequireAutoconfigCname { get; set; }

    /// <summary>Allowed suffixes for _autodiscover._tcp SRV target (e.g. outlook.com).</summary>
    [JsonPropertyName("allowedSrvTargetSuffixes")]
    public string[]? AllowedSrvTargetSuffixes { get; set; }

    /// <summary>Allowed suffixes for autodiscover.&lt;domain&gt; CNAME target (e.g. outlook.com).</summary>
    [JsonPropertyName("allowedAutodiscoverCnameTargetSuffixes")]
    public string[]? AllowedAutodiscoverCnameTargetSuffixes { get; set; }

    /// <summary>Allowed suffixes for autoconfig.&lt;domain&gt; CNAME target.</summary>
    [JsonPropertyName("allowedAutoconfigCnameTargetSuffixes")]
    public string[]? AllowedAutoconfigCnameTargetSuffixes { get; set; }

    /// <summary>When true, requires at least one Autodiscover endpoint to return valid XML or JSON.</summary>
    [JsonPropertyName("requireAnyValidEndpoint")]
    public bool? RequireAnyValidEndpoint { get; set; }

    /// <summary>Allowed suffixes for hosts of valid Autodiscover endpoints.</summary>
    [JsonPropertyName("allowedValidEndpointHostSuffixes")]
    public string[]? AllowedValidEndpointHostSuffixes { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateAutodiscoverPolicy Clone() {
        return new DesiredStateAutodiscoverPolicy {
            Enabled = Enabled,
            RequireSrvRecord = RequireSrvRecord,
            RequireAutodiscoverCname = RequireAutodiscoverCname,
            RequireAutoconfigCname = RequireAutoconfigCname,
            AllowedSrvTargetSuffixes = AllowedSrvTargetSuffixes != null ? (string[])AllowedSrvTargetSuffixes.Clone() : null,
            AllowedAutodiscoverCnameTargetSuffixes = AllowedAutodiscoverCnameTargetSuffixes != null ? (string[])AllowedAutodiscoverCnameTargetSuffixes.Clone() : null,
            AllowedAutoconfigCnameTargetSuffixes = AllowedAutoconfigCnameTargetSuffixes != null ? (string[])AllowedAutoconfigCnameTargetSuffixes.Clone() : null,
            RequireAnyValidEndpoint = RequireAnyValidEndpoint,
            AllowedValidEndpointHostSuffixes = AllowedValidEndpointHostSuffixes != null ? (string[])AllowedValidEndpointHostSuffixes.Clone() : null
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateAutodiscoverPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireSrvRecord.HasValue) RequireSrvRecord = overlay.RequireSrvRecord;
        if (overlay.RequireAutodiscoverCname.HasValue) RequireAutodiscoverCname = overlay.RequireAutodiscoverCname;
        if (overlay.RequireAutoconfigCname.HasValue) RequireAutoconfigCname = overlay.RequireAutoconfigCname;
        if (overlay.AllowedSrvTargetSuffixes != null) AllowedSrvTargetSuffixes = overlay.AllowedSrvTargetSuffixes;
        if (overlay.AllowedAutodiscoverCnameTargetSuffixes != null) AllowedAutodiscoverCnameTargetSuffixes = overlay.AllowedAutodiscoverCnameTargetSuffixes;
        if (overlay.AllowedAutoconfigCnameTargetSuffixes != null) AllowedAutoconfigCnameTargetSuffixes = overlay.AllowedAutoconfigCnameTargetSuffixes;
        if (overlay.RequireAnyValidEndpoint.HasValue) RequireAnyValidEndpoint = overlay.RequireAnyValidEndpoint;
        if (overlay.AllowedValidEndpointHostSuffixes != null) AllowedValidEndpointHostSuffixes = overlay.AllowedValidEndpointHostSuffixes;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireSrvRecord ??= false;
        RequireAutodiscoverCname ??= false;
        RequireAutoconfigCname ??= false;
        RequireAnyValidEndpoint ??= false;
    }
}

