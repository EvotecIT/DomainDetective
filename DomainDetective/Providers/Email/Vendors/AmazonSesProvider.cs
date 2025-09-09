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

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink { Url = null, Title = "ARC with SES", Summary = "No outbound ARC signing feature; ARC is typically for intermediaries.", Notes = "Focus on DMARC alignment via custom MAIL FROM (SPF) and DKIM.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-bimi.html", Title = "Using BIMI in Amazon SES", Summary = "BIMI prerequisites and steps for SES senders.", Notes = "Requires DMARC p=quarantine/reject; VMC typically required for Gmail/Apple display.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dmarc.html", Title = "Complying with DMARC in SES", Summary = "How DMARC alignment works with SES and setup steps.", Notes = "Use custom MAIL FROM for SPF alignment; also align via DKIM where possible.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-spf.html", Title = "Authenticating email with SPF in SES", Summary = "SPF and custom MAIL FROM domain configuration.", Notes = "Publish MX/SPF for MAIL FROM to receive bounces/complaints correctly.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html", Title = "Authenticating email with DKIM in SES", Summary = "Enable Easy DKIM and publish DNS keys.", Notes = "2048-bit supported; rotate keys and monitor alignment in VDM.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = "https://aws.amazon.com/blogs/security/three-ways-to-boost-your-email-security-and-brand-reputation-with-aws/", Title = "Boost email security: MTA-STS/TLS-RPT", Summary = "AWS blog patterns to host MTA-STS policy (e.g., S3/CloudFront) and enable TLS-RPT.", Notes = "Host policy at mta-sts.<domain>; test before enforce; pair with TLS-RPT.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = "https://aws.amazon.com/blogs/security/three-ways-to-boost-your-email-security-and-brand-reputation-with-aws/", Title = "TLS-RPT guidance", Summary = "Set up _smtp._tls TXT and analyze reports.", Notes = "Use SES VDM or third-party parsers to monitor TLS failures comprehensively.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://docs.aws.amazon.com/ses/latest/dg/send-email-concepts-deliverability.html", Title = "Understanding email deliverability in SES", Summary = "SES deliverability concepts and VDM feature overview.", Notes = "VDM offers dashboards and recommendations for reputation and inbox placement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
