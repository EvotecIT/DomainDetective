namespace DomainDetective.DesiredState;

internal static class DesiredStateCodes {
    public const string Conforms = "DesiredState.Conforms";

    public const string ConfigurationInvalid = "DesiredState.Configuration.Invalid";

    public const string DmarcMissingRecord = "DesiredState.DMARC.Record.Missing";
    public const string DmarcPolicyNotAllowed = "DesiredState.DMARC.Policy.NotAllowed";
    public const string DmarcSubPolicyNotAllowed = "DesiredState.DMARC.SubPolicy.NotAllowed";
    public const string DmarcSubPolicyMissing = "DesiredState.DMARC.SubPolicy.Missing";
    public const string DmarcAspfNotAllowed = "DesiredState.DMARC.ASPF.NotAllowed";
    public const string DmarcAdkimNotAllowed = "DesiredState.DMARC.ADKIM.NotAllowed";
    public const string DmarcRuaMissing = "DesiredState.DMARC.RUA.Missing";
    public const string DmarcRuaDomainNotAllowed = "DesiredState.DMARC.RUA.Domain.NotAllowed";
    public const string DmarcExternalReportUnauthorized = "DesiredState.DMARC.ExternalReport.Unauthorized";

    public const string SpfMissingRecord = "DesiredState.SPF.Record.Missing";
    public const string SpfAllMechanismNotAllowed = "DesiredState.SPF.All.NotAllowed";
    public const string SpfDnsLookupsExceeded = "DesiredState.SPF.DnsLookups.Exceeded";
    public const string SpfDenyAllRequired = "DesiredState.SPF.DenyAll.Required";
    public const string SpfRequiredIncludeMissing = "DesiredState.SPF.Include.Required.Missing";
    public const string SpfPtrNotAllowed = "DesiredState.SPF.PTR.NotAllowed";
    public const string SpfUnknownMechanismsNotAllowed = "DesiredState.SPF.Unknown.NotAllowed";
    public const string SpfRedirectNotAllowed = "DesiredState.SPF.Redirect.NotAllowed";
    public const string SpfRedirectRequired = "DesiredState.SPF.Redirect.Required";
    public const string SpfRedirectDomainNotAllowed = "DesiredState.SPF.Redirect.Domain.NotAllowed";

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

    public const string MxMissingRecord = "DesiredState.MX.Record.Missing";
    public const string MxNullMxRequired = "DesiredState.MX.NullMX.Required";
    public const string MxNullMxNotAllowed = "DesiredState.MX.NullMX.NotAllowed";
    public const string MxHostNotAllowed = "DesiredState.MX.Host.NotAllowed";
    public const string MxBackupServersRequired = "DesiredState.MX.Backup.Required";
    public const string MxIpv6Required = "DesiredState.MX.IPv6.Required";
    public const string MxTargetCnameNotAllowed = "DesiredState.MX.Target.CNAME.NotAllowed";
    public const string MxTargetIpNotAllowed = "DesiredState.MX.Target.IP.NotAllowed";
    public const string MxTargetNonExistent = "DesiredState.MX.Target.NonExistent";
    public const string MxTargetNoAddress = "DesiredState.MX.Target.NoAddress";
    public const string MxTargetLocalhostNotAllowed = "DesiredState.MX.Target.Localhost.NotAllowed";
    public const string MxTtlNotUniform = "DesiredState.MX.TTL.NotUniform";
    public const string MxRrsetInconsistent = "DesiredState.MX.RRSet.Inconsistent";
    public const string MxTargetAddressInconsistent = "DesiredState.MX.TargetAddress.Inconsistent";

    public const string NsMissingRecord = "DesiredState.NS.Record.Missing";
    public const string NsTooFewRecords = "DesiredState.NS.Records.TooFew";
    public const string NsDuplicatesNotAllowed = "DesiredState.NS.Records.Duplicate.NotAllowed";
    public const string NsMissingAddress = "DesiredState.NS.Target.NoAddress";
    public const string NsCnameTargetNotAllowed = "DesiredState.NS.Target.CNAME.NotAllowed";
    public const string NsDiversityRequired = "DesiredState.NS.Diversity.Required";
    public const string NsAsnDiversityTooLow = "DesiredState.NS.ASN.Diversity.TooLow";
    public const string NsHostNotAllowed = "DesiredState.NS.Host.NotAllowed";

    public const string CaaMissingRecord = "DesiredState.CAA.Record.Missing";
    public const string CaaPolicyInvalid = "DesiredState.CAA.Policy.Invalid";
    public const string CaaIssuerNotAllowed = "DesiredState.CAA.Issue.Issuer.NotAllowed";
    public const string CaaWildcardIssuerNotAllowed = "DesiredState.CAA.IssueWild.Issuer.NotAllowed";
    public const string CaaIodefMissing = "DesiredState.CAA.IODEF.Missing";
    public const string CaaIodefDomainNotAllowed = "DesiredState.CAA.IODEF.Domain.NotAllowed";

    public const string DnssecChainInvalid = "DesiredState.DNSSEC.Chain.Invalid";
    public const string DnssecRrsigExpiringSoon = "DesiredState.DNSSEC.RRSIG.DaysRemaining.TooLow";

    public const string SoaMissingRecord = "DesiredState.SOA.Record.Missing";
    public const string SoaSerialFormatInvalid = "DesiredState.SOA.Serial.Format.Invalid";
    public const string SoaRefreshOutOfRange = "DesiredState.SOA.Refresh.OutOfRange";
    public const string SoaRetryOutOfRange = "DesiredState.SOA.Retry.OutOfRange";
    public const string SoaExpireOutOfRange = "DesiredState.SOA.Expire.OutOfRange";
    public const string SoaMinimumOutOfRange = "DesiredState.SOA.Minimum.OutOfRange";

    public const string DaneMissingRecord = "DesiredState.DANE.Record.Missing";
    public const string DaneDuplicateNotAllowed = "DesiredState.DANE.Records.Duplicate.NotAllowed";
    public const string DaneInvalidRecords = "DesiredState.DANE.Records.Invalid";
    public const string DaneServiceMissingRecord = "DesiredState.DANE.Service.Record.Missing";
    public const string DaneSmtpRecommendedMissing = "DesiredState.DANE.SMTP.Recommended.Missing";
    public const string DaneHttpsRecommendedMissing = "DesiredState.DANE.HTTPS.Recommended.Missing";

    public const string DelegationMismatch = "DesiredState.DELEGATION.Parent.Mismatch";
    public const string DelegationGlueIncomplete = "DesiredState.DELEGATION.Glue.Incomplete";
    public const string DelegationGlueInconsistent = "DesiredState.DELEGATION.Glue.Inconsistent";

    public const string ZoneTransferAllowed = "DesiredState.ZONETRANSFER.AXFR.Allowed";

    public const string WildcardCatchAllRequired = "DesiredState.WILDCARDDNS.CatchAll.Required";
    public const string WildcardCatchAllNotAllowed = "DesiredState.WILDCARDDNS.CatchAll.NotAllowed";
}
