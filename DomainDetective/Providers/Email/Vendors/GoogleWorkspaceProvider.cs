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
    public string? DmarcHelpUrl => "https://support.google.com/a/answer/2466563";
}
