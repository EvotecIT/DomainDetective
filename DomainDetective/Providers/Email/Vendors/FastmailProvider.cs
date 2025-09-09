using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class FastmailProvider : IMailProvider
{
    public string Id => "fastmail";
    public string DisplayName => "Fastmail";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "in?.messagingengine.com",
        "*.messagingengine.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:spf.messagingengine.com" };
    public IEnumerable<string> DkimSelectorHints => new[] { "fm1", "fm2", "fm3" };
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://www.fastmail.help/hc/en-us/articles/360060591273-DMARC";
}
