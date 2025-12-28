using System;

namespace DomainDetective.Reports;

/// <summary>
/// Controls how vendor/provider reference material is embedded in Office-based reports
/// (Word/Excel). These options are typically derived from cmdlet parameters and influence
/// per-section placement as well as content density.
/// </summary>
public sealed class ProviderHelpRenderOptions
{
    // Placement controls
    /// <summary>Show provider help under MX section.</summary>
    public bool ShowUnderMx { get; set; } = true;
    /// <summary>Show provider help under SPF section.</summary>
    public bool ShowUnderSpf { get; set; } = true;
    /// <summary>Show provider help under DKIM section.</summary>
    public bool ShowUnderDkim { get; set; } = true;
    /// <summary>Show provider help under DMARC section.</summary>
    public bool ShowUnderDmarc { get; set; } = true;
    /// <summary>Show provider help under BIMI section (when present).</summary>
    public bool ShowUnderBimi { get; set; } = true;
    /// <summary>Show provider help under ARC section (when present).</summary>
    public bool ShowUnderArc { get; set; } = true;

    // Content controls
    /// <summary>Include short provider summaries.</summary>
    public bool ShowSummaries { get; set; } = true;
    /// <summary>Include provider notes and caveats.</summary>
    public bool ShowNotes { get; set; } = true;
    /// <summary>Include visual badges such as “Requires login” or “Third‑party”.</summary>
    public bool ShowBadges { get; set; } = true;
    /// <summary>Mark providers that are verified/endorsed when applicable.</summary>
    public bool ShowVerified { get; set; } = true;
    /// <summary>Include providers that have restricted availability.</summary>
    public bool IncludeRestricted { get; set; } = true;
    /// <summary>Include third‑party commercial providers.</summary>
    public bool IncludeThirdParty { get; set; } = true;

    /// <summary>Maximum number of providers to list under a section.</summary>
    public int MaxProviders { get; set; } = 6;

    /// <summary>Preferred ordering of topics/sections when rendering provider help.</summary>
    public string[] TopicOrder { get; set; } = new[] { "DMARC", "SPF", "DKIM", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "Deliverability" };
}
