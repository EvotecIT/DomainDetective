using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ZohoMailProvider : IMailProvider
{
    public string Id => "zoho-mail";
    public string DisplayName => "Zoho Mail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "mx.zoho.com",
        "mx2.zoho.com",
        "mx3.zoho.com",
        "mx.zoho.eu"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:zoho.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "zoho" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "zoho.com" };

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
            Url = "https://help.zoho.com/portal/en/kb/zoho-mail/zoho-mail-administrator-guide/domain-management/articles/dmarc-policy",
            Title = "DMARC policy – Secure email protocol",
            Summary = "Phased DMARC rollout guidance.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://help.zoho.com/portal/en/kb/zoho-mail/zoho-mail-administrator-guide/domain-management/articles/spf-record",
            Title = "SPF – Sender Policy Framework",
            Summary = "Use include:zohomail.com or include:one.zoho.com.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://help.zoho.com/portal/en/kb/zoho-mail/zoho-mail-administrator-guide/domain-management/articles/domainkeys-identified-mail-dkim",
            Title = "DKIM configuration to prevent email spoofing",
            Summary = "Create selector TXT at <selector>._domainkey.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://help.zoho.com/portal/en/kb/zoho-campaigns/campaign-management/deliverability/articles/email-deliverability",
            Title = "Email Deliverability",
            Summary = "General deliverability practices.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
