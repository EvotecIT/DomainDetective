using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

public sealed class CiscoSecureEmailProvider : IMailProvider
{
    public string Id => "cisco-secure-email";
    public string DisplayName => "Cisco Secure Email";
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.SpfPublish;

    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.iphmx.com",
        "*.secure.ironport.com",
        "*.emailsecurity.cisco.com",
        "*.esa.cisco.com"
    };

    public IEnumerable<string> SpfRequiredTokens => new string[0];
    public IEnumerable<string> DkimSelectorHints => new string[0];
    public IEnumerable<string> DkimCnameSuffixes => new[] { "emailsecurity.cisco.com", "ironport.com" };

    public bool SingleMxOk => false;
    public int RecommendedMinMxRecords => 2;
    public int MinimumDkimSelectorsToPass => 0;
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    public string? DmarcHelpUrl => null; // Removed pending replacement with public, stable URL
    public string? SpfHelpUrl => null;
    public string? DkimHelpUrl => null;
    public string? MtaStsHelpUrl => null;
    public string? TlsRptHelpUrl => null;
    public string? DeliverabilityHelpUrl => null;
}
