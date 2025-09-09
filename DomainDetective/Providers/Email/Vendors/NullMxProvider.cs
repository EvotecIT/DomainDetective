using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

// Represents RFC 7505 Null MX; included for completeness though detection is handled in MX analysis.
public sealed class NullMxProvider : IMailProvider
{
    public string Id => "null-mx";
    public string DisplayName => "Null MX";
    public ProviderCapability Capabilities => ProviderCapability.None;

    public IEnumerable<string> MxHostPatterns => new string[0];
    public IEnumerable<string> SpfRequiredTokens => new string[0];
    public IEnumerable<string> DkimSelectorHints => new string[0];
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

    public bool SingleMxOk => true;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.None;
    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink { Url = null, Title = "ARC", Summary = "Not applicable.", Notes = "No email service -> no ARC.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = null, Title = "BIMI", Summary = "Not applicable.", Notes = "No sending/receiving UX for BIMI.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = null, Title = "DMARC", Summary = "Optional for parked domains.", Notes = "Common pattern: p=reject to deter spoofing of non-mail domains.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf = new ProviderDocLink { Url = null, Title = "SPF", Summary = "Optional for parked domains.", Notes = "Common pattern: v=spf1 -all to signal 'do not send'.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim = new ProviderDocLink { Url = null, Title = "DKIM", Summary = "Not applicable.", Notes = "No sending = no DKIM.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "Not applicable.", Notes = "No inbound mail to secure.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "Not applicable.", Notes = "No inbound mail to report on.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://www.rfc-editor.org/rfc/rfc7505.html", Title = "RFC 7505 — Null MX", Summary = "How to publish 'No Service' MX for domains that accept no mail.", Notes = "Single MX preference 0 with exchange '.' to signal no mail acceptance.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
