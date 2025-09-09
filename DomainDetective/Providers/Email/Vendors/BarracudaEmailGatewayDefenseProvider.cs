using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class BarracudaEmailGatewayDefenseProvider : IMailProvider
{
    public string Id => "barracuda-egd";
    public string DisplayName => "Barracuda Email Gateway Defense";
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "ess*.barracudanetworks.com",
        "*.barracudanetworks.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        // Pattern varies by region; match base to raise confidence without overfitting
        "spf.ess",
        "barracudanetworks.com"
    };

    public IEnumerable<string> DkimSelectorHints => new string[0];
    public IEnumerable<string> DkimCnameSuffixes => new[] { "barracudanetworks.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://www.barracuda.com/glossary/dmarc",
            Title = "What is DMARC authentication?",
            Summary = "DMARC overview; enforcement modes.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
