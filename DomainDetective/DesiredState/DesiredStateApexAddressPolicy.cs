using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state apex address policy functionality.</summary>
public sealed class DesiredStateApexAddressPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, requires at least one apex A/AAAA record.</summary>
    [JsonPropertyName("requireAnyAddress")]
    public bool? RequireAnyAddress { get; set; }

    /// <summary>When true, disallows any apex A/AAAA records (useful for non-web / parked domains).</summary>
    [JsonPropertyName("disallowAnyAddress")]
    public bool? DisallowAnyAddress { get; set; }

    /// <summary>Gets or sets the disallow private addresses value.</summary>
    [JsonPropertyName("disallowPrivateAddresses")]
    public bool? DisallowPrivateAddresses { get; set; }

    /// <summary>Gets or sets the disallow loopback addresses value.</summary>
    [JsonPropertyName("disallowLoopbackAddresses")]
    public bool? DisallowLoopbackAddresses { get; set; }

    /// <summary>Gets or sets the disallow link local addresses value.</summary>
    [JsonPropertyName("disallowLinkLocalAddresses")]
    public bool? DisallowLinkLocalAddresses { get; set; }

    /// <summary>Gets or sets the disallow multicast addresses value.</summary>
    [JsonPropertyName("disallowMulticastAddresses")]
    public bool? DisallowMulticastAddresses { get; set; }

    /// <summary>Gets or sets the disallow documentation addresses value.</summary>
    [JsonPropertyName("disallowDocumentationAddresses")]
    public bool? DisallowDocumentationAddresses { get; set; }

    /// <summary>Gets or sets the disallow unique local v6 addresses value.</summary>
    [JsonPropertyName("disallowUniqueLocalV6Addresses")]
    public bool? DisallowUniqueLocalV6Addresses { get; set; }

    /// <summary>Minimum distinct subnet count for apex IPv4 addresses.</summary>
    [JsonPropertyName("minDistinctSubnetCountV4")]
    public int? MinDistinctSubnetCountV4 { get; set; }

    /// <summary>Minimum distinct subnet count for apex IPv6 addresses.</summary>
    [JsonPropertyName("minDistinctSubnetCountV6")]
    public int? MinDistinctSubnetCountV6 { get; set; }

    /// <summary>When true, requires PTR records to exist for all discovered apex addresses.</summary>
    [JsonPropertyName("requireAllPtrPresent")]
    public bool? RequireAllPtrPresent { get; set; }

    /// <summary>When true, requires forward-confirmed reverse DNS for all discovered apex addresses.</summary>
    [JsonPropertyName("requireAllFcrDnsValid")]
    public bool? RequireAllFcrDnsValid { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateApexAddressPolicy Clone() {
        return new DesiredStateApexAddressPolicy {
            Enabled = Enabled,
            RequireAnyAddress = RequireAnyAddress,
            DisallowAnyAddress = DisallowAnyAddress,
            DisallowPrivateAddresses = DisallowPrivateAddresses,
            DisallowLoopbackAddresses = DisallowLoopbackAddresses,
            DisallowLinkLocalAddresses = DisallowLinkLocalAddresses,
            DisallowMulticastAddresses = DisallowMulticastAddresses,
            DisallowDocumentationAddresses = DisallowDocumentationAddresses,
            DisallowUniqueLocalV6Addresses = DisallowUniqueLocalV6Addresses,
            MinDistinctSubnetCountV4 = MinDistinctSubnetCountV4,
            MinDistinctSubnetCountV6 = MinDistinctSubnetCountV6,
            RequireAllPtrPresent = RequireAllPtrPresent,
            RequireAllFcrDnsValid = RequireAllFcrDnsValid
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateApexAddressPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAnyAddress.HasValue) RequireAnyAddress = overlay.RequireAnyAddress;
        if (overlay.DisallowAnyAddress.HasValue) DisallowAnyAddress = overlay.DisallowAnyAddress;
        if (overlay.DisallowPrivateAddresses.HasValue) DisallowPrivateAddresses = overlay.DisallowPrivateAddresses;
        if (overlay.DisallowLoopbackAddresses.HasValue) DisallowLoopbackAddresses = overlay.DisallowLoopbackAddresses;
        if (overlay.DisallowLinkLocalAddresses.HasValue) DisallowLinkLocalAddresses = overlay.DisallowLinkLocalAddresses;
        if (overlay.DisallowMulticastAddresses.HasValue) DisallowMulticastAddresses = overlay.DisallowMulticastAddresses;
        if (overlay.DisallowDocumentationAddresses.HasValue) DisallowDocumentationAddresses = overlay.DisallowDocumentationAddresses;
        if (overlay.DisallowUniqueLocalV6Addresses.HasValue) DisallowUniqueLocalV6Addresses = overlay.DisallowUniqueLocalV6Addresses;
        if (overlay.MinDistinctSubnetCountV4.HasValue) MinDistinctSubnetCountV4 = overlay.MinDistinctSubnetCountV4;
        if (overlay.MinDistinctSubnetCountV6.HasValue) MinDistinctSubnetCountV6 = overlay.MinDistinctSubnetCountV6;
        if (overlay.RequireAllPtrPresent.HasValue) RequireAllPtrPresent = overlay.RequireAllPtrPresent;
        if (overlay.RequireAllFcrDnsValid.HasValue) RequireAllFcrDnsValid = overlay.RequireAllFcrDnsValid;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAnyAddress ??= false;
        DisallowAnyAddress ??= false;
        DisallowPrivateAddresses ??= true;
        DisallowLoopbackAddresses ??= true;
        DisallowLinkLocalAddresses ??= true;
        DisallowMulticastAddresses ??= true;
        DisallowDocumentationAddresses ??= true;
        DisallowUniqueLocalV6Addresses ??= true;
        RequireAllPtrPresent ??= false;
        RequireAllFcrDnsValid ??= false;
    }
}

