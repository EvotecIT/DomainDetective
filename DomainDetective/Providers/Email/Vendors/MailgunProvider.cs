using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class MailgunProvider : IMailProvider
{
    public string Id => "mailgun";
    public string DisplayName => "Mailgun";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[] { "include:mailgun.org" };
    public IEnumerable<string> DkimSelectorHints => new[] { "krs", "mg" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mailgun.org" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
}

