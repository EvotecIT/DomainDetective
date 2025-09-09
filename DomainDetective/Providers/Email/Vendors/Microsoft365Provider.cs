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
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email";
    public string? SpfHelpUrl => "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing";
    public string? DkimHelpUrl => "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email";
    public string? MtaStsHelpUrl => "https://learn.microsoft.com/en-us/microsoft-365/exchange/enhancing-mail-flow-security-mta-sts";
    public string? TlsRptHelpUrl => "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/dane-for-smtp?view=o365-worldwide#smtp-tls-reporting";
    public string? DeliverabilityHelpUrl => "https://sendersupport.olc.protection.outlook.com/pm/services.aspx";
}
