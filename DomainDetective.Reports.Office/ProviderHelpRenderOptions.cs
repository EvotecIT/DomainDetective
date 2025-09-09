namespace DomainDetective.Reports.Office;

public sealed class ProviderHelpRenderOptions
{
    // Placement controls
    public bool ShowUnderMx { get; set; } = true;
    public bool ShowUnderSpf { get; set; } = true;
    public bool ShowUnderDkim { get; set; } = true;
    public bool ShowUnderDmarc { get; set; } = true;
    public bool ShowUnderBimi { get; set; } = true;
    public bool ShowUnderArc { get; set; } = true;

    // Content controls
    public bool ShowSummaries { get; set; } = true;
    public bool ShowNotes { get; set; } = true;
    public bool ShowBadges { get; set; } = true; // [Requires login] / [Third‑party]
    public bool ShowVerified { get; set; } = true;
    public bool IncludeRestricted { get; set; } = true;
    public bool IncludeThirdParty { get; set; } = true;

    public int MaxProviders { get; set; } = 6;

    public string[] TopicOrder { get; set; } = new[] { "DMARC", "SPF", "DKIM", "ARC", "BIMI", "MTA-STS", "TLS-RPT", "Deliverability" };
}
