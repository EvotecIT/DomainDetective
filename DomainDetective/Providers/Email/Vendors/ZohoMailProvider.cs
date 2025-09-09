using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ZohoMailProvider : IMailProvider
{
    public string Id => "zoho-mail";
    public string DisplayName => "Zoho Mail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "mx.zoho.com",
        "mx2.zoho.com",
        "mx3.zoho.com",
        "mx.zoho.eu"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:zoho.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "zoho" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "zoho.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://www.zoho.com/mail/help/adminconsole/dmarc.html";
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
