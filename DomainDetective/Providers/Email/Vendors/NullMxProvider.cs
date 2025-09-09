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
    public ProviderDocumentation Docs => new ProviderDocumentation { Provider = DisplayName };
}
