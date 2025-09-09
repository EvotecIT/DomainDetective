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

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink { Url = "https://postmarkapp.com/blog/what-is-arc-or-authenticated-received-chain", Title = "What is ARC?", Summary = "ARC explainer for forwarding scenarios.", Notes = "Postmark does not require sender-domain SPF includes; focus on DKIM alignment.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://postmarkapp.com/blog/what-the-heck-is-bimi-and-why-is-it-so-important", Title = "What is BIMI?", Summary = "BIMI overview and prerequisites for display.", Notes = "Configure via DNS/VMC; not a Postmark UI feature.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://postmarkapp.com/support/article/892-what-is-dmarc", Title = "What is DMARC?", Summary = "DMARC basics and monitoring options.", Notes = "Use Postmark DMARC monitor or third-party tools for reports.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://postmarkapp.com/support/article/1102-why-is-it-not-required-to-include-postmark-in-our-own-custom-spf-record", Title = "Why it’s not required to include Postmark in your SPF", Summary = "SPF alignment via Return-Path/bounce domain; no sender-domain include needed.", Notes = "Rely on DKIM for DMARC alignment; avoid unnecessary SPF bloat.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://postmarkapp.com/support/article/1091-how-do-i-set-up-dkim-for-postmark", Title = "How do I set up DKIM for Postmark?", Summary = "Obtain and publish DKIM TXT records for your domain in Postmark and then enable.", Notes = "Rotate keys and verify DNS propagation before enforcement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No Postmark-specific MTA-STS admin doc.", Notes = "Implement at your domain for inbound; independent of Postmark.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No Postmark-specific TLS-RPT page.", Notes = "Add _smtp._tls TXT and parse reports with your tooling.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://postmarkapp.com/support", Title = "Postmark Support Center", Summary = "Central docs for sending/deliverability & best practices.", Notes = "See DKIM/Return-Path articles and DMARC monitor resources.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
