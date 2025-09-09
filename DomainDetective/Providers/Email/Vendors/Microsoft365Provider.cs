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

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure",
            Title = "Configure trusted ARC sealers",
            Summary = "How to trust ARC sealers in Exchange Online so ARC can inform authentication.",
            Notes = "Inbound ARC evaluation with admin trust list; ARC results appear in anti-spam headers.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink {
            Url = null,
            Title = "BIMI in Microsoft 365",
            Summary = "No official end-user BIMI display documentation for Outlook/Exchange Online.",
            Notes = "Outlook.com discussions suggest limited/experimental support; treat as unsupported until Microsoft publishes guidance.",
            IsPublic = true, IsThirdParty = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dmarc = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure",
            Title = "Use DMARC to validate email",
            Summary = "DMARC setup and troubleshooting for Exchange Online.",
            Notes = "Pair with ARC trust if using intermediaries.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure",
            Title = "Set up SPF for Microsoft 365",
            Summary = "Publish SPF including Microsoft 365 senders.",
            Notes = "Canonical include: include:spf.protection.outlook.com; mind the 10-lookup limit.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure",
            Title = "Set up DKIM for Microsoft 365",
            Summary = "Create CNAMEs and enable DKIM for custom domains.",
            Notes = "Default selectors often selector1/selector2; 2048-bit supported.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/purview/enhancing-mail-flow-with-mta-sts",
            Title = "Enhancing mail flow with MTA-STS",
            Summary = "MTA-STS overview and adoption for Exchange Online contexts.",
            Notes = "Publish _mta-sts TXT and host policy at mta-sts.<domain> over HTTPS.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/purview/enhancing-mail-flow-with-mta-sts",
            Title = "MTA-STS/TLS-RPT overview",
            Summary = "TLS-RPT basics and relation to MTA-STS.",
            Notes = "Add _smtp._tls TXT to receive aggregate TLS reports.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink {
            Url = "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about",
            Title = "Email authentication in Microsoft Defender for Office 365",
            Summary = "How Microsoft evaluates SPF, DKIM, DMARC, ARC and headers.",
            Notes = "See also Outlook Postmaster services for SNDS/JMRP: https://sendersupport.olc.protection.outlook.com/pm/services.aspx",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
