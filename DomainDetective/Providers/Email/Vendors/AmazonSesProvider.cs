using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class AmazonSesProvider : IMailProvider
{
    public string Id => "amazon-ses";
    public string DisplayName => "Amazon SES";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:amazonses.com" };
    public IEnumerable<string> DkimSelectorHints => new[] { "s1", "s2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "amazonses.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
}

