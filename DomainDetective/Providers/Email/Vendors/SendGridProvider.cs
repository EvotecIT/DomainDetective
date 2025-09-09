using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class SendGridProvider : IMailProvider
{
    public string Id => "sendgrid";
    public string DisplayName => "SendGrid";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:sendgrid.net"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "s1", "s2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "sendgrid.net" };

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
            Url = "https://support.sendgrid.com/hc/en-us/articles/203663556-What-is-SPF-and-DMARC-",
            Title = "Internet standards (SPF & DMARC)",
            Summary = "DMARC defaults and SPF sanity limits.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://support.sendgrid.com/hc/en-us/articles/203365330-How-to-Set-Up-Domain-Authentication",
            Title = "How to Set Up Domain Authentication",
            Summary = "CNAME selectors s1/s2; optional TXT SPF.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://support.sendgrid.com/hc/en-us/articles/203033398-DKIM-Records-Explained",
            Title = "DKIM Records Explained",
            Summary = "Automated security uses CNAME DKIM.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://sendgrid.com/blog/guide-to-email-deliverability/",
            Title = "Guide to email deliverability",
            Summary = "Consent, list hygiene, segmentation.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
