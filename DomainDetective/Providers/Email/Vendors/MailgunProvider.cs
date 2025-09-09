using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class MailgunProvider : IMailProvider
{
    public string Id => "mailgun";
    public string DisplayName => "Mailgun";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:mailgun.org" };
    public IEnumerable<string> DkimSelectorHints => new[] { "krs", "mg" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mailgun.org" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://help.mailgun.com/hc/en-us/articles/202052074-How-do-I-set-up-DMARC";
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
