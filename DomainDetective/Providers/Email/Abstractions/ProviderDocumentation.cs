using System;

namespace DomainDetective.Providers.Email;

public sealed class ProviderDocLink
{
    public string? Url { get; set; }
    public string? Title { get; set; }
    public string? Summary { get; set; }
    public string? Notes { get; set; }
    public bool IsPublic { get; set; } = true;
    public bool IsThirdParty { get; set; } = false;
    public DateTime? LastVerified { get; set; }
}

public sealed class ProviderDocumentation
{
    public string? Provider { get; set; }
    public ProviderDocLink? Dmarc { get; set; }
    public ProviderDocLink? Spf { get; set; }
    public ProviderDocLink? Dkim { get; set; }
    public ProviderDocLink? MtaSts { get; set; }
    public ProviderDocLink? TlsRpt { get; set; }
    public ProviderDocLink? Deliverability { get; set; }

    public ProviderDocLink? Get(string topic)
    {
        if (string.IsNullOrWhiteSpace(topic)) return null;
        switch (topic.Trim().ToUpperInvariant())
        {
            case "DMARC": return Dmarc;
            case "SPF": return Spf;
            case "DKIM": return Dkim;
            case "MTA-STS": return MtaSts;
            case "TLS-RPT": return TlsRpt;
            case "DELIVERABILITY": return Deliverability;
            default: return null;
        }
    }
}

