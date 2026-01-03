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

    public const string DkimNoSelectors = "DesiredState.DKIM.Selector.None";
    public const string DkimSelectorMissing = "DesiredState.DKIM.Selector.Missing";
    public const string DkimKeyBitsTooLow = "DesiredState.DKIM.KeyBits.TooLow";
    public const string DkimCnameTargetNotAllowed = "DesiredState.DKIM.CNAME.Target.NotAllowed";

    public const string MtastsMissingRecord = "DesiredState.MTASTS.Record.Missing";
    public const string MtastsEnforceRequired = "DesiredState.MTASTS.Mode.Enforce.Required";
    public const string MtastsMaxAgeTooLow = "DesiredState.MTASTS.MaxAge.TooLow";
    public const string MtastsMxNotAligned = "DesiredState.MTASTS.MX.NotAligned";

    public const string TlsRptMissingRecord = "DesiredState.TLSRPT.Record.Missing";
    public const string TlsRptRuaMissing = "DesiredState.TLSRPT.RUA.Missing";
    public const string TlsRptPolicyInvalid = "DesiredState.TLSRPT.Policy.Invalid";
    public const string TlsRptRuaDomainNotAllowed = "DesiredState.TLSRPT.RUA.Domain.NotAllowed";

    public const string BimiMissingRecord = "DesiredState.BIMI.Record.Missing";
    public const string BimiIndicatorDeclined = "DesiredState.BIMI.Indicator.Declined";
    public const string BimiLocationInvalid = "DesiredState.BIMI.Location.Invalid";
    public const string BimiLocationHostNotAllowed = "DesiredState.BIMI.Location.Host.NotAllowed";
    public const string BimiAuthorityMissing = "DesiredState.BIMI.Authority.Missing";
    public const string BimiAuthorityHostNotAllowed = "DesiredState.BIMI.Authority.Host.NotAllowed";
}
