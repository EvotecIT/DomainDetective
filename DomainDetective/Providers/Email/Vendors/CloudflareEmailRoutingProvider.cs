using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class CloudflareEmailRoutingProvider : IMailProvider
{
    public string Id => "cloudflare-email-routing";
    public string DisplayName => "Cloudflare Email Routing";
    public ProviderCapability Capabilities => ProviderCapability.InboundMx;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "route*.mx.cloudflare.net",
        "*.mx.cloudflare.net",
        "*.mailchannels.net"
    };

    public IEnumerable<string> SpfRequiredTokens => new string[0];
    public IEnumerable<string> DkimSelectorHints => new string[0];
    public IEnumerable<string> DkimCnameSuffixes => new string[0];

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://developers.cloudflare.com/email-security/dmarc/";
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
