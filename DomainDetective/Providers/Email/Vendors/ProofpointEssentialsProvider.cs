using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class ProofpointEssentialsProvider : IMailProvider {
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
    // Documentation (source of truth)
    public ProviderDocumentation Docs => new ProviderDocumentation
    {
        Provider = DisplayName,
        Dmarc = new ProviderDocLink
        {
            Url = "https://www.proofpoint.com/sites/default/files/proofpoint-essentials-dmarc-implementation-guide.pdf",
            Title = "How to Implement DMARC",
            Summary = "DMARC deployment steps and sample records.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Spf = new ProviderDocLink
        {
            Url = "https://essentials.proofpoint.com/portal#/connectiondetails",
            Title = "Connection Details (SPF includes)",
            Summary = "Region‑specific SPF include tokens.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        },
        Deliverability = new ProviderDocLink
        {
            Url = "https://help.proofpoint.com/Proofpoint_Essentials/Admin_Topic_Center/Email_Policies/040/Inbound_Anti-Spoofing",
            Title = "Configuring Inbound Anti‑Spoofing",
            Summary = "Respect DMARC; handle DKIM/SPF failures.",
            IsPublic = true,
            LastVerified = new System.DateTime(2025, 9, 9)
        }
    };
}
