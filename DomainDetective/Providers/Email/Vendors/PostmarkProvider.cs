using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class PostmarkProvider : IMailProvider
{
    public string Id => "postmark";
    public string DisplayName => "Postmark";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:spf.mtasv.net" };
    public IEnumerable<string> DkimSelectorHints => new[] { "pm" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "pm.mtasv.net" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
}

