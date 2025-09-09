using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class CloudflareEmailRoutingProvider : IMailProvider {
    public string Id => "cloudflare-email-routing";
    public string DisplayName => "Cloudflare Email Routing";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "route*.mx.cloudflare.net",
        "*.mx.cloudflare.net",
        "*.mailchannels.net"
    };

    public IEnumerable<string> SpfRequiredTokens => new string[0];
    public IEnumerable<string> DkimSelectorHints => new string[0];
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)
    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster",
            Title = "Postmaster (DMARC/SPF/DKIM)",
            Summary = "Cloudflare forwards only authenticated mail; DMARC enforced.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9),
        },
        Spf = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster",
            Title = "Postmaster (SPF)",
            Summary = "include:_spf.mx.cloudflare.net.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9),
        },
        Dkim = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster",
            Title = "Postmaster (DKIM)",
            Summary = "DKIM for email.cloudflare.net; ARC supported.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9),
        },
        MtaSts = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster/mta-sts",
            Title = "Configure MTA‑STS",
            Summary = "CNAME _mta-sts to _mta-sts.mx.cloudflare.net; host policy.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9),
        },
        // Cloudflare Email Routing: TLS‑RPT not documented publicly (omit or set Url=null)
        TlsRpt = null,
        Deliverability = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster",
            Title = "Postmaster (Deliverability/ARC)",
            Summary = "ARC headers; IP ranges; anti‑spam measures.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9),
        },
    };
}
