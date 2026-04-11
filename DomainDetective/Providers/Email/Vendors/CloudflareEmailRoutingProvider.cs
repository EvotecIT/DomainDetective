using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides cloudflare email routing provider functionality.</summary>
public sealed class CloudflareEmailRoutingProvider : IMailProvider {
    /// <summary>Represents the id value.</summary>
    public string Id => "cloudflare-email-routing";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Cloudflare Email Routing";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.InboundMx;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "route*.mx.cloudflare.net",
        "*.mx.cloudflare.net",
        "*.mailchannels.net"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new string[0];
    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new string[0];
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

    /// <summary>Represents the single mx ok value.</summary>
    public bool SingleMxOk => false;
    /// <summary>Represents the recommended min mx records value.</summary>
    public int RecommendedMinMxRecords => 2;
    /// <summary>Represents the minimum dkim selectors to pass value.</summary>
    public int MinimumDkimSelectorsToPass => 0;
    /// <summary>Represents the subdomain policy recommendation value.</summary>
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)
    /// <summary>Represents the docs value.</summary>
    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster/",
            Title = "Postmaster — ARC support",
            Summary = "Describes how Cloudflare Email Routing adds ARC headers to forwarded mail to preserve authentication.",
            Notes = "ARC helps receiving providers verify forwarded messages; there are no user controls for ARC on outbound mail.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink { Url = null, Title = "BIMI", Summary = "Cloudflare Email Routing is a forwarding service and does not implement BIMI itself.", Notes = "BIMI must be configured on the sender domain via DNS and a VMC; display is controlled by recipient mailbox providers.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/dmarc-management/security-records/",
            Title = "Configure email security records (DMARC)",
            Summary = "Guide to publishing DMARC, SPF and DKIM records in Cloudflare DNS using the DMARC Management app.",
            Notes = "This helps administrators manage email authentication records; actual DMARC enforcement still depends on the sending service.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/dmarc-management/security-records/",
            Title = "Configure email security records (SPF)",
            Summary = "Instructions for adding an SPF record via Cloudflare DNS.",
            Notes = "Use flattening or other methods to avoid exceeding the 10 DNS lookup limit; ensure only one SPF record exists per domain.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/dmarc-management/security-records/",
            Title = "Configure email security records (DKIM)",
            Summary = "Explain how to publish DKIM TXT records in Cloudflare DNS.",
            Notes = "DKIM keys and selectors are provided by your email sending service; rotate keys regularly.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/setup/mta-sts/",
            Title = "Configure MTA-STS",
            Summary = "Shows how to publish _mta‑sts DNS records and host MTA‑STS policy files using Cloudflare Email Routing and Workers.",
            Notes = "A CNAME is provided to point to Cloudflare’s hosted record; you still need to host the policy file on a secure domain.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "Cloudflare does not provide a specific TLS‑RPT documentation.", Notes = "Administrators should publish a _smtp._tls TXT record to receive TLS reports; use third‑party services to parse them.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink {
            Url = "https://developers.cloudflare.com/email-routing/postmaster/",
            Title = "Postmaster",
            Summary = "Explains how Cloudflare Email Routing preserves authentication results and describes service behavior.",
            Notes = "Cloudflare Email Routing forwards mail using ARC headers and maintains DMARC alignment when possible; deliverability relies on the original sender’s authentication records.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
