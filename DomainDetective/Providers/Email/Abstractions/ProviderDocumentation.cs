using System;

namespace DomainDetective.Providers.Email;

/// <summary>Provides provider doc link functionality.</summary>
public sealed class ProviderDocLink
{
    /// <summary>Gets or sets the url value.</summary>
    public string? Url { get; set; }
    /// <summary>Gets or sets the title value.</summary>
    public string? Title { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string? Summary { get; set; }
    /// <summary>Gets or sets the notes value.</summary>
    public string? Notes { get; set; }
    /// <summary>Gets or sets the is public value.</summary>
    public bool IsPublic { get; set; } = true;
    /// <summary>Gets or sets the is third party value.</summary>
    public bool IsThirdParty { get; set; } = false;
    /// <summary>Gets or sets the last verified value.</summary>
    public DateTime? LastVerified { get; set; }
}

/// <summary>Provides provider documentation functionality.</summary>
public sealed class ProviderDocumentation
{
    /// <summary>Gets or sets the provider value.</summary>
    public string? Provider { get; set; }
    // Core outbound/inbound authentication & transport
    /// <summary>Gets or sets the dmarc value.</summary>
    public ProviderDocLink? Dmarc { get; set; }
    /// <summary>Gets or sets the spf value.</summary>
    public ProviderDocLink? Spf { get; set; }
    /// <summary>Gets or sets the dkim value.</summary>
    public ProviderDocLink? Dkim { get; set; }
    /// <summary>Gets or sets the arc value.</summary>
    public ProviderDocLink? Arc { get; set; }
    /// <summary>Gets or sets the bimi value.</summary>
    public ProviderDocLink? Bimi { get; set; }
    /// <summary>Gets or sets the mta sts value.</summary>
    public ProviderDocLink? MtaSts { get; set; }
    /// <summary>Gets or sets the tls rpt value.</summary>
    public ProviderDocLink? TlsRpt { get; set; }
    /// <summary>Gets or sets the deliverability value.</summary>
    public ProviderDocLink? Deliverability { get; set; }

    /// <summary>Executes the get operation.</summary>
    public ProviderDocLink? Get(string topic)
    {
        if (string.IsNullOrWhiteSpace(topic)) return null;
        switch (topic.Trim().ToUpperInvariant())
        {
            case "DMARC": return Dmarc;
            case "SPF": return Spf;
            case "DKIM": return Dkim;
            case "ARC": return Arc;
            case "BIMI": return Bimi;
            case "MTA-STS": return MtaSts;
            case "TLS-RPT": return TlsRpt;
            case "DELIVERABILITY": return Deliverability;
            default: return null;
        }
    }
}
