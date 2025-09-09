using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ProofpointEssentialsProvider : IMailProvider
{
    public string Id => "proofpoint-essentials";
    public string DisplayName => "Proofpoint Essentials";
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.ppe-hosted.com",
        "ppe-hosted.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        // Proofpoint Essentials publishes SPF guidance that typically references ppe-hosted.com includes
        "ppe-hosted.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "pp", "proofpoint" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "pphosted.com", "proofpoint.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://help.proofpoint.com/Email_Protection/Administrator_Guide/Email_Authentication_DMARC";
}
