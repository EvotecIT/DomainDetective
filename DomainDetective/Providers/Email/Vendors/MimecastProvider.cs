using System;
using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class MimecastProvider : IMailProvider
{
    public string Id => "mimecast";
    public string DisplayName => "Mimecast";
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.mimecast.com",
        "inbound*.mimecast.com",
        "mx*.mimecast.com",
        "us-smtp-inbound-*.mimecast.com"
    };

    public IEnumerable<string> SpfRequiredTokens => Array.Empty<string>();

    public IEnumerable<string> DkimSelectorHints => Array.Empty<string>();
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mimecast.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
}
