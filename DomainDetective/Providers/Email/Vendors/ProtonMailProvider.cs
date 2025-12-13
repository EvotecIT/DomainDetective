using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ProtonMailProvider : IMailProvider
{
    public string Id => "protonmail";
    public string DisplayName => "Proton Mail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "mx1.protonmail.ch",
        "mx2.protonmail.ch"
    };

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:_spf.protonmail.ch" };
    public IEnumerable<string> DkimSelectorHints => new[] { "protonmail", "protonmail1", "protonmail2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "protonmail.ch" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink {
            Url = "https://proton.me/blog/what-is-authenticated-received-chain-arc",
            Title = "Authenticated Received Chain (ARC) — all you need to know",
            Summary = "Proton explains ARC and its role in forwarding/mailing lists.",
            Notes = "No sender-side ARC controls; Proton uses ARC in filtering pipelines.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink { Url = null, Title = "BIMI with Proton", Summary = "No Proton first-party BIMI setup page.", Notes = "Implement BIMI DNS + VMC for receivers that display (Gmail/Apple/Yahoo).", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink {
            Url = "https://proton.me/support/custom-domain",
            Title = "How to use a custom domain with Proton Mail",
            Summary = "SPF/DKIM/DMARC setup for custom domains; Proton recommends p=quarantine.",
            Notes = "Proton provides three DKIM records; ensure only one SPF TXT exists for the domain.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://proton.me/support/custom-domain",
            Title = "Custom domain setup (SPF/DKIM/DMARC)",
            Summary = "SPF, DKIM, DMARC requirements summarized for Proton senders.",
            Notes = "Follow tenant-specific include/mechanisms shown in the UI; keep lookups ≤ 10.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://proton.me/support/custom-domain",
            Title = "Custom domain setup (DKIM)",
            Summary = "Publish all Proton-provided DKIM records and enable signing.",
            Notes = "Use 2048-bit keys where supported; rotate periodically.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink {
            Url = "https://proton.me/blog/security-updates-2019",
            Title = "Security updates (MTA-STS mention)",
            Summary = "Context on MTA-STS; policy is hosted at your domain.",
            Notes = "Implement standard MTA-STS/TLS-RPT on your zone; Proton supports TLS transport.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink {
            Url = "https://proton.me/blog/why-are-my-emails-going-to-spam",
            Title = "Why are my emails going to spam?",
            Summary = "Deliverability guidance that references transport/auth best practices.",
            Notes = "Add _smtp._tls TXT to receive TLS reports; analyze with tooling.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink {
            Url = "https://proton.me/support/email-sending-limits",
            Title = "Proton Mail sending limits",
            Summary = "Plan/abuse-based sending constraints affecting deliverability.",
            Notes = "Respect rate limits to avoid throttling/blocks; maintain positive reputation signals.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
