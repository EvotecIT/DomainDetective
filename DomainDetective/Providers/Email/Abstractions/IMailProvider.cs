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

    // Optional DMARC subdomain policy guidance
    DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation { get; }

    // Optional: official DMARC guidance/help page from the provider
    string? DmarcHelpUrl { get; }

    // Optional: official SPF guidance/help page
    string? SpfHelpUrl { get; }
    // Optional: official DKIM guidance/help page
    string? DkimHelpUrl { get; }
    // Optional: official MTA-STS guidance/help page
    string? MtaStsHelpUrl { get; }
    // Optional: official TLSRPT guidance/help page
    string? TlsRptHelpUrl { get; }
    // Optional: deliverability/postmaster/best practices page
    string? DeliverabilityHelpUrl { get; }
}
