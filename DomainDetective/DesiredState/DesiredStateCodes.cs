namespace DomainDetective.DesiredState;

internal static class DesiredStateCodes {
    public const string Conforms = "DesiredState.Conforms";

    public const string ConfigurationInvalid = "DesiredState.Configuration.Invalid";

    public const string DmarcMissingRecord = "DesiredState.DMARC.Record.Missing";
    public const string DmarcPolicyNotAllowed = "DesiredState.DMARC.Policy.NotAllowed";
    public const string DmarcRuaMissing = "DesiredState.DMARC.RUA.Missing";
    public const string DmarcRuaDomainNotAllowed = "DesiredState.DMARC.RUA.Domain.NotAllowed";
    public const string DmarcExternalReportUnauthorized = "DesiredState.DMARC.ExternalReport.Unauthorized";

    public const string SpfMissingRecord = "DesiredState.SPF.Record.Missing";
    public const string SpfAllMechanismNotAllowed = "DesiredState.SPF.All.NotAllowed";
    public const string SpfDnsLookupsExceeded = "DesiredState.SPF.DnsLookups.Exceeded";
    public const string SpfDenyAllRequired = "DesiredState.SPF.DenyAll.Required";
}

