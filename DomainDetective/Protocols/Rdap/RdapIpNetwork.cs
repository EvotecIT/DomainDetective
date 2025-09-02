namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// Represents an IP network object in RDAP.
/// </summary>
public sealed class RdapIpNetwork
{
    private string? _cidr;
    /// <summary>Starting IP address.</summary>
    [JsonPropertyName("startAddress")]
    public string? StartAddress { get; set; }

    /// <summary>Ending IP address.</summary>
    [JsonPropertyName("endAddress")]
    public string? EndAddress { get; set; }

    /// <summary>CIDR notation for the network.</summary>
    [JsonPropertyName("cidr")]
    public string? Cidr {
        get {
            if (!string.IsNullOrEmpty(_cidr)) return _cidr;
            if (Cidr0Cidrs != null && Cidr0Cidrs.Length > 0) {
                var parts = new System.Collections.Generic.List<string>();
                foreach (var c in Cidr0Cidrs) {
                    if (!string.IsNullOrEmpty(c.V4Prefix) && c.Length.HasValue) parts.Add($"{c.V4Prefix}/{c.Length.Value}");
                    else if (!string.IsNullOrEmpty(c.V6Prefix) && c.Length.HasValue) parts.Add($"{c.V6Prefix}/{c.Length.Value}");
                }
                return parts.Count > 0 ? string.Join(", ", parts) : null;
            }
            return null;
        }
        set { _cidr = value; }
    }

    /// <summary>ARIN/extension style list of CIDR entries.</summary>
    [JsonPropertyName("cidr0_cidrs")]
    public RdapCidr0[]? Cidr0Cidrs { get; set; }

    /// <summary>Country code when provided by RDAP service.</summary>
    [JsonPropertyName("country")]
    public string? Country { get; set; }

    /// <summary>Display name when provided.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Entities associated with this IP network (may include ASN orgs).</summary>
    [JsonPropertyName("entities")]
    public RdapEntity[]? Entities { get; set; }
}

/// <summary>
/// RDAP extension structure for CIDR notation entries.
/// See: https://www.arin.net/resources/registry/whois/rdap/ (cidr0)
/// </summary>
public sealed class RdapCidr0 {
    [JsonPropertyName("v4prefix")]
    public string? V4Prefix { get; set; }
    [JsonPropertyName("v6prefix")]
    public string? V6Prefix { get; set; }
    [JsonPropertyName("length")]
    public int? Length { get; set; }
}
}
