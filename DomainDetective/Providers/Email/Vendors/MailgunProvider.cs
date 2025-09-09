using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class MailgunProvider : IMailProvider
{
    public string Id => "mailgun";
    public string DisplayName => "Mailgun";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:mailgun.org" };
    public IEnumerable<string> DkimSelectorHints => new[] { "krs", "mg" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mailgun.org" };

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
            Url = "https://help.mailgun.com/hc/en-us/articles/360010222013-Domain-based-Message-Authentication-Reporting-and-Conformance-DMARC",
            Title = "DMARC (Mailgun)",
            Summary = "DMARC policy options; example record.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://help.mailgun.com/hc/en-us/articles/360011197673-How-do-I-configure-DNS-records-for-my-sending-domains-",
            Title = "Configure DNS records (SPF)",
            Summary = "include:mailgun.org in SPF.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://help.mailgun.com/hc/en-us/articles/1500002514942-What-is-DKIM-key-rotation-and-what-do-I-need-to-do-",
            Title = "DKIM key rotation",
            Summary = "CNAME pdk1/pdk2; 2048‑bit; 120‑day rotation.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://help.mailgun.com/hc/en-us/articles/360012703393-Tips-for-Better-Deliverability",
            Title = "Tips for Better Deliverability",
            Summary = "Warm-up, double opt‑in, list hygiene.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
