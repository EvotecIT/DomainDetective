using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class SendGridProvider : IMailProvider
{
    public string Id => "sendgrid";
    public string DisplayName => "SendGrid";
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new string[0];

    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:sendgrid.net"
    };

    public IEnumerable<string> DkimSelectorHints => new[] { "s1", "s2" };
    public IEnumerable<string> DkimCnameSuffixes => new[] { "sendgrid.net" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 0;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://docs.sendgrid.com/ui/sending-email/sender-authentication#dmarc";
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
