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

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://support.google.com/a/answer/2466563",
            Title = "Set up DMARC",
            Summary = "Add _dmarc TXT; phased rollout.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://support.google.com/a/answer/33786",
            Title = "Set up SPF",
            Summary = "Publish v=spf1 include:_spf.google.com",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink
        {
            Url = "https://support.google.com/a/answer/174124",
            Title = "Set up DKIM",
            Summary = "Generate keys; default selector google.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink
        {
            Url = "https://support.google.com/a/answer/9261504",
            Title = "About MTA‑STS and TLS reporting",
            Summary = "Overview and reasons to enable.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink
        {
            Url = "https://support.google.com/a/answer/9276512",
            Title = "Turn on MTA‑STS and TLS reporting",
            Summary = "Add _smtp._tls and _mta-sts TXT; policy id usage.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://support.google.com/a/topic/2683820",
            Title = "Top 10 Gmail sender issues",
            Summary = "Best practices and Postmaster Tools.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
