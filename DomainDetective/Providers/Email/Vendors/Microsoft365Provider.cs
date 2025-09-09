using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class Microsoft365Provider : IMailProvider
{
    public string Id => "m365";
    public string DisplayName => "Microsoft 365";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.mail.protection.outlook.com",
        "mail.eo.outlook.com",
        "*mx.microsoft*"
    };

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:spf.protection.outlook.com"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "selector1", "selector2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "onmicrosoft.com", "protection.outlook.com", "outlook.com" };

    public bool SingleMxOk => true;
    public int RecommendedMinMxRecords => 1;
    public int MinimumDkimSelectorsToPass => 1;
}
