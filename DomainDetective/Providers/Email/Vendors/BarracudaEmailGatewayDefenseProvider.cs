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
    public string? DmarcHelpUrl => null; // Removed pending replacement with public, stable URL
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
