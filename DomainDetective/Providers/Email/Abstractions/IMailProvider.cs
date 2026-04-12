using System.Collections.Generic;

namespace DomainDetective.Providers.Email;

/// <summary>Defines the contract for i mail provider.</summary>
public interface IMailProvider
{
    /// <summary>Gets the id value.</summary>
    string Id { get; }
    /// <summary>Gets the display name value.</summary>
    string DisplayName { get; }
    /// <summary>Gets the capabilities value.</summary>
    ProviderCapability Capabilities { get; }

    // Fingerprints
    /// <summary>Gets the mx host patterns value.</summary>
    IEnumerable<string> MxHostPatterns { get; }
    /// <summary>Gets the spf required tokens value.</summary>
    IEnumerable<string> SpfRequiredTokens { get; }
    /// <summary>Gets the dkim selector hints value.</summary>
    IEnumerable<string> DkimSelectorHints { get; }
    /// <summary>Gets the dkim cname suffixes value.</summary>
    IEnumerable<string> DkimCnameSuffixes { get; }

    // Policy allowances
    /// <summary>Gets the single mx ok value.</summary>
    bool SingleMxOk { get; }
    /// <summary>Gets the recommended min mx records value.</summary>
    int RecommendedMinMxRecords { get; }

    // Optional DKIM policy hints for narratives/rules
    /// <summary>Gets the minimum dkim selectors to pass value.</summary>
    int MinimumDkimSelectorsToPass { get; }

    // Optional DMARC subdomain policy guidance
    /// <summary>Gets the subdomain policy recommendation value.</summary>
    DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation { get; }

    // Rich documentation metadata (source of truth for links)
    /// <summary>Gets the docs value.</summary>
    ProviderDocumentation Docs { get; }
}
