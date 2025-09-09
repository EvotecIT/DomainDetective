using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class AmazonSesProvider : IMailProvider
{
    public string Id => "amazon-ses";
    public string DisplayName => "Amazon SES";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:amazonses.com" };
    public IEnumerable<string> DkimSelectorHints => new[] { "s1", "s2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "amazonses.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://repost.aws/knowledge-center/ses-dmarc-spf-dkim-alignment",
            Title = "DMARC alignment for SPF and DKIM",
            Summary = "Alignment requirements and recommendations.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://repost.aws/knowledge-center/ses-send-dkim-verification-fail",
            Title = "SES Easy DKIM & BYO DKIM",
            Summary = "Easy DKIM; 2048‑bit keys; BYODKIM.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://repost.aws/knowledge-center/ses-migrate-improve-deliverability",
            Title = "Migrate email and improve deliverability",
            Summary = "Verification, production access, warming.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
