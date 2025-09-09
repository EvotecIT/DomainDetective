using System;
using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class MimecastProvider : IMailProvider
{
    public string Id => "mimecast";
    public string DisplayName => "Mimecast";
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.mimecast.com",
        "inbound*.mimecast.com",
        "mx*.mimecast.com",
        "us-smtp-inbound-*.mimecast.com"
    };

    public IEnumerable<string> SpfRequiredTokens => Array.Empty<string>();

    public IEnumerable<string> DkimSelectorHints => Array.Empty<string>();
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mimecast.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dkim = new ProviderDocLink
        {
            Url = "https://support.mimecast.com/s/article/Policies-Configuring-DNS-Authentication-Definition",
            Title = "Configuring DNS Authentication (DKIM)",
            Summary = "Generate keys; publish selector._domainkey TXT.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink
        {
            Url = "https://support.mimecast.com/s/article/Policies-MTA-STS-Overview",
            Title = "MTA‑STS Overview",
            Summary = "_mta-sts TXT and policy; TLS‑RPT guidance.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink
        {
            Url = "https://support.mimecast.com/s/article/Policies-MTA-STS-Overview",
            Title = "MTA‑STS / TLS‑RPT",
            Summary = "_smtp._tls TXT with TLSRPTv1.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://support.mimecast.com/s/article/Email-Delivery-Policies-Guide-on-Hard-Bounces-and-Troubleshooting",
            Title = "Email Delivery Policies & Troubleshooting",
            Summary = "Hard/soft bounces and remediation.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
