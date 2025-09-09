using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ProtonMailProvider : IMailProvider
{
    public string Id => "protonmail";
    public string DisplayName => "Proton Mail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "mx1.protonmail.ch",
        "mx2.protonmail.ch"
    };

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:_spf.protonmail.ch" };
    public IEnumerable<string> DkimSelectorHints => new[] { "protonmail", "protonmail1", "protonmail2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "protonmail.ch" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://proton.me/support/dmarc";
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
