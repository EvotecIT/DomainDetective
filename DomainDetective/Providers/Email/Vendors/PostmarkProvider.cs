using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class PostmarkProvider : IMailProvider
{
    public string Id => "postmark";
    public string DisplayName => "Postmark";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:spf.mtasv.net" };
    public IEnumerable<string> DkimSelectorHints => new[] { "pm" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "pm.mtasv.net" };

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
            Url = "https://postmarkapp.com/support/article/892-what-is-dmarc",
            Title = "What is DMARC?",
            Summary = "DMARC tags and rollout guidance.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://postmarkapp.com/support/article/1092-how-do-i-set-up-spf-for-postmark",
            Title = "How do I set up SPF for Postmark?",
            Summary = "SPF passes by default; custom Return‑Path for alignment.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://postmarkapp.com/support/article/1091-how-do-i-set-up-dkim-for-postmark",
            Title = "How do I set up DKIM for Postmark?",
            Summary = "Publish pm._domainkey TXT; 1024‑bit RSA.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://postmarkapp.com/guides/how-to-improve-domain-reputation-for-better-email-deliverability",
            Title = "Improve domain reputation",
            Summary = "Warm-up, consistent volume, Postmaster tools.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
