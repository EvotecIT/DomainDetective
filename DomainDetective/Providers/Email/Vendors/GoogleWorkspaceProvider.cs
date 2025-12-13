using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class GoogleWorkspaceProvider : IMailProvider
{
    public string Id => "googleworkspace";
    public string DisplayName => "Google Workspace";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "aspmx.l.google.com",
        "alt1.aspmx.l.google.com",
        "alt2.aspmx.l.google.com",
        "alt3.aspmx.l.google.com",
        "alt4.aspmx.l.google.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:_spf.google.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "google" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "google.com", "googlemail.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;

    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/81126",
            Title = "Email sender guidelines (ARC behavior)",
            Summary = "How Gmail evaluates ARC on forwarded mail alongside its own checks.",
            Notes = "ARC doesn’t automatically authenticate; Gmail still checks SPF/DKIM/DMARC.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/10911320",
            Title = "Set up BIMI",
            Summary = "Steps to enable BIMI with VMC/CMC and BIMI TXT.",
            Notes = "Requires DMARC p=quarantine/reject; upload VMC/CMC; see SVG requirements & TXT details.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dmarc = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/2466580",
            Title = "Set up DMARC",
            Summary = "Workspace DMARC guidance for staged rollout and enforcement.",
            Notes = "Ensure SPF/DKIM are in place 48+ hours before raising DMARC policy.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/33786",
            Title = "Set up SPF",
            Summary = "SPF record with include:_spf.google.com and examples.",
            Notes = "Keep total DNS lookups ≤ 10; consolidate third-party senders carefully.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/174124",
            Title = "Set up DKIM",
            Summary = "Generate and publish Workspace DKIM; rotate keys.",
            Notes = "2048-bit keys recommended; default selector often 'google'.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/9261504",
            Title = "About MTA-STS and TLS reporting",
            Summary = "Publish MTA-STS policy and related DNS labels.",
            Notes = "Policy at https://mta-sts.<domain>/.well-known/mta-sts.txt; add _mta-sts TXT.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/9261504",
            Title = "About MTA-STS and TLS reporting",
            Summary = "Enable TLS-RPT via _smtp._tls TXT and monitor failures.",
            Notes = "Reports are sent by other MTAs to your rua mailbox; ensure capacity/aggregation.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink {
            Url = "https://support.google.com/a/answer/14289100",
            Title = "Email sender guidelines & Postmaster Tools",
            Summary = "Bulk sender rules and reputation monitoring.",
            Notes = "Use Postmaster Tools dashboards for spam rate, domain/IP reputation and feedback loop insights.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
