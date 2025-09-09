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

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink {
            Url = "https://www.fastmail.help/hc/en-us/articles/1500000280461-Sender-authentication",
            Title = "Sender authentication",
            Summary = "Fastmail evaluates SPF, DKIM, DMARC and ARC on inbound; adds Authentication-Results.",
            Notes = "ARC considered in spam scoring; see blog for deeper ARC background.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink {
            Url = "https://www.fastmail.help/hc/en-us/articles/7002542139663-Using-BIMI-in-Fastmail",
            Title = "Using BIMI in Fastmail",
            Summary = "Requirements and steps for BIMI with Fastmail-hosted domains.",
            Notes = "Requires SPF/DKIM + DMARC enforcement; VMC needed for display at some receivers.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dmarc = new ProviderDocLink {
            Url = "https://www.fastmail.help/hc/en-us/articles/8703749889807-DMARC",
            Title = "DMARC in Fastmail",
            Summary = "DMARC overview and setup (especially if Fastmail manages DNS).",
            Notes = "When Fastmail manages DNS, default p=none is common; enforce after monitoring.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://www.fastmail.com/help/receive/domains-advanced.html",
            Title = "Manual DNS configuration",
            Summary = "SPF example: v=spf1 include:spf.messagingengine.com …",
            Notes = "Keep lookups ≤ 10; combine third-party includes carefully.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://www.fastmail.com/blog/dkim-signing-outgoing-email-with-from-address-domain/",
            Title = "DKIM signing outgoing email",
            Summary = "Fastmail uses selector “mesmtp”; DKIM keys managed per domain.",
            Notes = "Many setups publish fm1/fm2/fm3 CNAMEs per Fastmail instructions.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No Fastmail-specific MTA-STS admin doc.", Notes = "Implement standard MTA-STS at your domain; pair with TLS-RPT before enforce.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No Fastmail-specific TLS-RPT doc.", Notes = "Publish _smtp._tls TXT and aggregate reports with your tooling.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink {
            Url = "https://www.fastmail.help/hc/en-us/categories/1500000036522-Setup",
            Title = "Setup guides (domain/auth)",
            Summary = "Consolidated domain, auth and best-practice docs.",
            Notes = "See also 'The email delivery process' and ARC blog for analysis context.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
