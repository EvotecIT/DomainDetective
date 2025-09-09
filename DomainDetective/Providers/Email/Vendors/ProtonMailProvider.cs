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
    // Documentation (source of truth)

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://proton.me/support/anti-spoofing-custom-domain",
            Title = "Anti‑spoofing for custom domains (DMARC)",
            Summary = "Start with p=none; enforce later.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://proton.me/support/anti-spoofing-custom-domain",
            Title = "Anti‑spoofing (SPF)",
            Summary = "include:_spf.protonmail.ch mx ~all.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://proton.me/support/anti-spoofing-custom-domain",
            Title = "Anti‑spoofing (DKIM)",
            Summary = "Three CNAMEs; 2048‑bit; rotation.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
