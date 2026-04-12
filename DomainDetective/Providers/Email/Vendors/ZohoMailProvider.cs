using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides zoho mail provider functionality.</summary>
public sealed class ZohoMailProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "zoho-mail";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Zoho Mail";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "mx.zoho.com",
        "mx2.zoho.com",
        "mx3.zoho.com",
        "mx.zoho.eu"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:zoho.com"
    };

    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new[] { "zoho" };
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "zoho.com" };

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
            Url = "https://help.zoho.com/portal/en/community/topic/2024-email-authentication-standards-elevating-security-with-google-and-yahoo-22-1-2024",
            Title = "2024 email authentication standards (ARC mention)",
            Summary = "Zoho’s guidance referencing ARC in forwarding contexts.",
            Notes = "Admin ARC controls limited; primarily relevant to intermediaries and receivers.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Bimi = new ProviderDocLink {
            Url = "https://www.zoho.com/mail/help/adminconsole/advanced-security-configuration.html",
            Title = "Advanced email configuration (BIMI)",
            Summary = "Where BIMI settings live and pre-requisites.",
            Notes = "Requires DMARC enforcement; VMC often needed for display by major receivers.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dmarc = new ProviderDocLink {
            Url = "https://www.zoho.com/mail/help/adminconsole/dmarc-policy.html",
            Title = "DMARC policy",
            Summary = "Zoho DMARC setup and policy phases.",
            Notes = "UI supports none/quarantine/reject with reporting configuration.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink {
            Url = "https://www.zoho.com/mail/help/adminconsole/spf-configuration.html",
            Title = "SPF configuration",
            Summary = "Zoho SPF overview and record details.",
            Notes = "Some Zoho apps use specific include tokens; verify per product/tenant.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Dkim = new ProviderDocLink {
            Url = "https://www.zoho.com/mail/help/adminconsole/dkim-configuration.html",
            Title = "DKIM configuration",
            Summary = "Add selector, publish TXT, and enable signing.",
            Notes = "1024/2048-bit supported depending on DNS host; rotate keys periodically.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        MtaSts = new ProviderDocLink {
            Url = null,
            Title = "MTA-STS",
            Summary = "No first-party Zoho MTA-STS setup doc.",
            Notes = "Implement standard MTA-STS (_mta-sts TXT + hosted policy) at your domain; independent of Zoho hosting.",
            IsPublic = true, IsThirdParty = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        TlsRpt = new ProviderDocLink {
            Url = null,
            Title = "TLS-RPT",
            Summary = "No first-party Zoho TLS-RPT doc.",
            Notes = "Add _smtp._tls TXT to receive reports; parse with internal/third-party tooling.",
            IsPublic = true, IsThirdParty = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink {
            Url = "https://www.zoho.com/mail/help/guidelines-spam-control.html",
            Title = "Spam control — guidelines and best practices",
            Summary = "Zoho deliverability and authentication guidance.",
            Notes = "Covers reputation, list hygiene and auth requirements.",
            IsPublic = true, IsThirdParty = false,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
