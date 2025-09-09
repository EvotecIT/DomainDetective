using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class FastmailProvider : IMailProvider
{
    public string Id => "fastmail";
    public string DisplayName => "Fastmail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "in?.messagingengine.com",
        "*.messagingengine.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:spf.messagingengine.com" };
    public IEnumerable<string> DkimSelectorHints => new[] { "fm1", "fm2", "fm3" };
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

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
            Url = "https://www.fastmail.help/hc/en-us/articles/360058752434-DMARC",
            Title = "DMARC",
            Summary = "Default p=none; publish custom DMARC for enforcement.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://www.fastmail.help/hc/en-us/articles/360060121214-Manual-DNS-configuration",
            Title = "Manual DNS configuration (SPF)",
            Summary = "SPF uses include:spf.messagingengine.com.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://www.fastmail.help/hc/en-us/articles/360060121214-Manual-DNS-configuration",
            Title = "Manual DNS configuration (DKIM)",
            Summary = "Selectors fm1/fm2/fm3 via CNAME.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://www.fastmail.help/hc/en-us/articles/360060066154-Bounce-messages",
            Title = "Bounce messages",
            Summary = "Troubleshooting delivery failures.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
