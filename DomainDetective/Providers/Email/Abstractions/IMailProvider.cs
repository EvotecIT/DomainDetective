using System.Collections.Generic;

namespace DomainDetective.Providers.Email;

public interface IMailProvider
{
    string Id { get; }
    string DisplayName { get; }
    ProviderCapability Capabilities { get; }

    // Fingerprints
    IEnumerable<string> MxHostPatterns { get; }
    IEnumerable<string> SpfRequiredTokens { get; }
    IEnumerable<string> DkimSelectorHints { get; }
    IEnumerable<string> DkimCnameSuffixes { get; }

    // Policy allowances
    bool SingleMxOk { get; }
    int RecommendedMinMxRecords { get; }

    // Optional DKIM policy hints for narratives/rules
    int MinimumDkimSelectorsToPass { get; }
}
