using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class Microsoft365Provider : IMailProvider {
    public string Id => "m365";
    public string DisplayName => "Microsoft 365";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.mail.protection.outlook.com",
        "mail.eo.outlook.com",
        "*mx.microsoft*"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:spf.protection.outlook.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "selector1", "selector2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "onmicrosoft.com", "protection.outlook.com", "outlook.com" };

    public bool SingleMxOk => true;
    public int RecommendedMinMxRecords => 1;
    public int MinimumDkimSelectorsToPass => 1;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email",
            Title = "Use DMARC to validate email",
            Summary = "How to publish a _dmarc TXT and configure DMARC policies.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing",
            Title = "Set up SPF to identify valid email sources",
            Summary = "Create SPF with include:spf.protection.outlook.com and -all.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email",
            Title = "How to use DKIM for your custom domain",
            Summary = "Create selector1/selector2 CNAMEs; rotate keys.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink
        {
            Url = "https://learn.microsoft.com/en-us/microsoft-365/exchange/enhancing-mail-flow-security-mta-sts",
            Title = "Enhancing mail flow security with MTA‑STS",
            Summary = "Publish _mta-sts TXT and host STSv1 policy.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink
        {
            Url = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/dane-for-smtp?view=o365-worldwide#smtp-tls-reporting",
            Title = "SMTP TLS reporting",
            Summary = "Publish _smtp._tls TXT with v=TLSRPTv1; rua=…",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://sendersupport.olc.protection.outlook.com/pm/services.aspx",
            Title = "Outlook.com services for senders and ISPs",
            Summary = "Postmaster/SNDS/JMRP resources.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
