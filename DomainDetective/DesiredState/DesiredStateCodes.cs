namespace DomainDetective.DesiredState;

internal static class DesiredStateCodes {
    public const string Conforms = "DesiredState.Conforms";

    public const string ConfigurationInvalid = "DesiredState.Configuration.Invalid";

    public const string DmarcMissingRecord = "DesiredState.DMARC.Record.Missing";
    public const string DmarcInvalidRecord = "DesiredState.DMARC.Record.Invalid";
    public const string DmarcMultipleRecordsNotAllowed = "DesiredState.DMARC.Record.Multiple.NotAllowed";
    public const string DmarcRecordTooLong = "DesiredState.DMARC.Record.Length.TooLong";
    public const string DmarcPolicyNotAllowed = "DesiredState.DMARC.Policy.NotAllowed";
    public const string DmarcSubPolicyNotAllowed = "DesiredState.DMARC.SubPolicy.NotAllowed";
    public const string DmarcSubPolicyMissing = "DesiredState.DMARC.SubPolicy.Missing";
    public const string DmarcAspfNotAllowed = "DesiredState.DMARC.ASPF.NotAllowed";
    public const string DmarcAdkimNotAllowed = "DesiredState.DMARC.ADKIM.NotAllowed";
    public const string DmarcRuaMissing = "DesiredState.DMARC.RUA.Missing";
    public const string DmarcMailtoRuaMissing = "DesiredState.DMARC.RUA.Mailto.Missing";
    public const string DmarcHttpRuaNotAllowed = "DesiredState.DMARC.RUA.HTTPS.NotAllowed";
    public const string DmarcRuaDomainNotAllowed = "DesiredState.DMARC.RUA.Domain.NotAllowed";
    public const string DmarcExternalReportUnauthorized = "DesiredState.DMARC.ExternalReport.Unauthorized";
    public const string DmarcRufNotAllowed = "DesiredState.DMARC.RUF.NotAllowed";
    public const string DmarcHttpRufNotAllowed = "DesiredState.DMARC.RUF.HTTPS.NotAllowed";
    public const string DmarcWeakPolicyNotAllowed = "DesiredState.DMARC.Policy.Weak.NotAllowed";
    public const string DmarcUnknownTagsNotAllowed = "DesiredState.DMARC.Tags.Unknown.NotAllowed";
    public const string DmarcDeprecatedTagsNotAllowed = "DesiredState.DMARC.Tags.Deprecated.NotAllowed";

    public const string SpfMissingRecord = "DesiredState.SPF.Record.Missing";
    public const string SpfInvalidRecord = "DesiredState.SPF.Record.Invalid";
    public const string SpfMultipleRecordsNotAllowed = "DesiredState.SPF.Record.Multiple.NotAllowed";
    public const string SpfEffectiveSendingRequired = "DesiredState.SPF.EffectiveSending.Required";
    public const string SpfAllMechanismNotAllowed = "DesiredState.SPF.All.NotAllowed";
    public const string SpfAllMechanismMissing = "DesiredState.SPF.All.Missing";
    public const string SpfDnsLookupsExceeded = "DesiredState.SPF.DnsLookups.Exceeded";
    public const string SpfDenyAllRequired = "DesiredState.SPF.DenyAll.Required";
    public const string SpfRequiredIncludeMissing = "DesiredState.SPF.Include.Required.Missing";
    public const string SpfPtrNotAllowed = "DesiredState.SPF.PTR.NotAllowed";
    public const string SpfUnknownMechanismsNotAllowed = "DesiredState.SPF.Unknown.NotAllowed";
    public const string SpfRedirectNotAllowed = "DesiredState.SPF.Redirect.NotAllowed";
    public const string SpfRedirectRequired = "DesiredState.SPF.Redirect.Required";
    public const string SpfRedirectDomainNotAllowed = "DesiredState.SPF.Redirect.Domain.NotAllowed";
    public const string SpfExpNotAllowed = "DesiredState.SPF.EXP.NotAllowed";
    public const string SpfPermErrorNotAllowed = "DesiredState.SPF.PermError.NotAllowed";
    public const string SpfCnameNotAllowed = "DesiredState.SPF.CNAME.NotAllowed";

    public const string DkimNoSelectors = "DesiredState.DKIM.Selector.None";
    public const string DkimSelectorMissing = "DesiredState.DKIM.Selector.Missing";
    public const string DkimStartsInvalid = "DesiredState.DKIM.Record.Starts.Invalid";
    public const string DkimPublicKeyMissing = "DesiredState.DKIM.PublicKey.Missing";
    public const string DkimPublicKeyInvalid = "DesiredState.DKIM.PublicKey.Invalid";
    public const string DkimKeyTypeInvalid = "DesiredState.DKIM.KeyType.Invalid";
    public const string DkimKeyBitsTooLow = "DesiredState.DKIM.KeyBits.TooLow";
    public const string DkimWeakKeyNotAllowed = "DesiredState.DKIM.KeyBits.Weak.NotAllowed";
    public const string DkimKeyTooOld = "DesiredState.DKIM.KeyAge.TooHigh";
    public const string DkimDeprecatedTagsNotAllowed = "DesiredState.DKIM.Tags.Deprecated.NotAllowed";
    public const string DkimFlagsInvalid = "DesiredState.DKIM.Flags.Invalid";
    public const string DkimCanonicalizationInvalid = "DesiredState.DKIM.Canonicalization.Invalid";
    public const string DkimCanonicalizationUnknownNotAllowed = "DesiredState.DKIM.Canonicalization.Unknown.NotAllowed";
    public const string DkimCnameTargetNotAllowed = "DesiredState.DKIM.CNAME.Target.NotAllowed";

    public const string MtastsMissingRecord = "DesiredState.MTASTS.Record.Missing";
    public const string MtastsDnsRecordInvalid = "DesiredState.MTASTS.Record.Invalid";
    public const string MtastsPolicyMissing = "DesiredState.MTASTS.Policy.Missing";
    public const string MtastsPolicyInvalid = "DesiredState.MTASTS.Policy.Invalid";
    public const string MtastsDuplicateFieldsNotAllowed = "DesiredState.MTASTS.Fields.Duplicate.NotAllowed";
    public const string MtastsEnforceRequired = "DesiredState.MTASTS.Mode.Enforce.Required";
    public const string MtastsMaxAgeTooLow = "DesiredState.MTASTS.MaxAge.TooLow";
    public const string MtastsMxNotAligned = "DesiredState.MTASTS.MX.NotAligned";

    public const string TlsRptMissingRecord = "DesiredState.TLSRPT.Record.Missing";
    public const string TlsRptMultipleRecordsNotAllowed = "DesiredState.TLSRPT.Record.Multiple.NotAllowed";
    public const string TlsRptRecordTooLong = "DesiredState.TLSRPT.Record.Length.TooLong";
    public const string TlsRptRuaMissing = "DesiredState.TLSRPT.RUA.Missing";
    public const string TlsRptMailtoRuaMissing = "DesiredState.TLSRPT.RUA.Mailto.Missing";
    public const string TlsRptPolicyInvalid = "DesiredState.TLSRPT.Policy.Invalid";
    public const string TlsRptInvalidRuaNotAllowed = "DesiredState.TLSRPT.RUA.Invalid.NotAllowed";
    public const string TlsRptUnknownTagsNotAllowed = "DesiredState.TLSRPT.Tags.Unknown.NotAllowed";
    public const string TlsRptHttpRuaNotAllowed = "DesiredState.TLSRPT.RUA.HTTPS.NotAllowed";
    public const string TlsRptRuaDomainNotAllowed = "DesiredState.TLSRPT.RUA.Domain.NotAllowed";

    public const string BimiMissingRecord = "DesiredState.BIMI.Record.Missing";
    public const string BimiIndicatorDeclined = "DesiredState.BIMI.Indicator.Declined";
    public const string BimiLocationInvalid = "DesiredState.BIMI.Location.Invalid";
    public const string BimiLocationHostNotAllowed = "DesiredState.BIMI.Location.Host.NotAllowed";
    public const string BimiAuthorityMissing = "DesiredState.BIMI.Authority.Missing";
    public const string BimiAuthorityHostNotAllowed = "DesiredState.BIMI.Authority.Host.NotAllowed";

    public const string StartTlsNoResults = "DesiredState.STARTTLS.Results.None";
    public const string StartTlsAnySupportedRequired = "DesiredState.STARTTLS.Supported.Any.Required";
    public const string StartTlsAllSupportedRequired = "DesiredState.STARTTLS.Supported.All.Required";
    public const string StartTlsDowngradeNotAllowed = "DesiredState.STARTTLS.Downgrade.NotAllowed";

    public const string SmtpTlsNoResults = "DesiredState.SMTPTLS.Results.None";
    public const string SmtpTlsCertificateInvalid = "DesiredState.SMTPTLS.Certificate.Invalid";
    public const string SmtpTlsChainInvalid = "DesiredState.SMTPTLS.Certificate.Chain.Invalid";
    public const string SmtpTlsHostnameMismatch = "DesiredState.SMTPTLS.Certificate.Hostname.Mismatch";
    public const string SmtpTlsCertificateExpired = "DesiredState.SMTPTLS.Certificate.Expired";
    public const string SmtpTlsCertificateExpiringSoon = "DesiredState.SMTPTLS.Certificate.DaysRemaining.TooLow";
    public const string SmtpTlsLegacyNotAllowed = "DesiredState.SMTPTLS.Legacy.NotAllowed";
    public const string SmtpTlsGradeTooLow = "DesiredState.SMTPTLS.Grade.TooLow";

    public const string ImapTlsNoResults = "DesiredState.IMAPTLS.Results.None";
    public const string ImapTlsCertificateInvalid = "DesiredState.IMAPTLS.Certificate.Invalid";
    public const string ImapTlsChainInvalid = "DesiredState.IMAPTLS.Certificate.Chain.Invalid";
    public const string ImapTlsHostnameMismatch = "DesiredState.IMAPTLS.Certificate.Hostname.Mismatch";
    public const string ImapTlsCertificateExpired = "DesiredState.IMAPTLS.Certificate.Expired";
    public const string ImapTlsCertificateExpiringSoon = "DesiredState.IMAPTLS.Certificate.DaysRemaining.TooLow";
    public const string ImapTlsLegacyNotAllowed = "DesiredState.IMAPTLS.Legacy.NotAllowed";
    public const string ImapTlsGradeTooLow = "DesiredState.IMAPTLS.Grade.TooLow";

    public const string Pop3TlsNoResults = "DesiredState.POP3TLS.Results.None";
    public const string Pop3TlsCertificateInvalid = "DesiredState.POP3TLS.Certificate.Invalid";
    public const string Pop3TlsChainInvalid = "DesiredState.POP3TLS.Certificate.Chain.Invalid";
    public const string Pop3TlsHostnameMismatch = "DesiredState.POP3TLS.Certificate.Hostname.Mismatch";
    public const string Pop3TlsCertificateExpired = "DesiredState.POP3TLS.Certificate.Expired";
    public const string Pop3TlsCertificateExpiringSoon = "DesiredState.POP3TLS.Certificate.DaysRemaining.TooLow";
    public const string Pop3TlsLegacyNotAllowed = "DesiredState.POP3TLS.Legacy.NotAllowed";
    public const string Pop3TlsGradeTooLow = "DesiredState.POP3TLS.Grade.TooLow";

    public const string SmtpBannerNoResults = "DesiredState.SMTPBANNER.Results.None";
    public const string SmtpBannerFormatInvalid = "DesiredState.SMTPBANNER.Format.Invalid";
    public const string SmtpBannerGreetingNot220 = "DesiredState.SMTPBANNER.Greeting.Not220";
    public const string SmtpBannerDomainMissing = "DesiredState.SMTPBANNER.Domain.Missing";
    public const string SmtpBannerTruncatedNotAllowed = "DesiredState.SMTPBANNER.Truncated.NotAllowed";
    public const string SmtpBannerResponseTimeTooHigh = "DesiredState.SMTPBANNER.ResponseTime.TooHigh";
    public const string SmtpBannerTlsNotAdvertised = "DesiredState.SMTPBANNER.TLS.NotAdvertised";
    public const string SmtpBannerServerDomainNotAllowed = "DesiredState.SMTPBANNER.ServerDomain.NotAllowed";
    public const string SmtpBannerVersionLeakNotAllowed = "DesiredState.SMTPBANNER.VersionLeaked.NotAllowed";

    public const string SmtpAuthNoResults = "DesiredState.SMTPAUTH.Results.None";
    public const string SmtpAuthAdvertisementNotAllowed = "DesiredState.SMTPAUTH.Advertisement.NotAllowed";
    public const string SmtpAuthMechanismNotAllowed = "DesiredState.SMTPAUTH.Mechanism.NotAllowed";
    public const string SmtpAuthMechanismUnexpected = "DesiredState.SMTPAUTH.Mechanism.Unexpected";
    public const string SmtpAuthRequiredMechanismMissing = "DesiredState.SMTPAUTH.Mechanism.Required.Missing";
    public const string SmtpAuthCapabilitiesMissing = "DesiredState.SMTPAUTH.Capabilities.Missing";
    public const string SmtpAuthStartTlsRequired = "DesiredState.SMTPAUTH.STARTTLS.Required";

    public const string OpenRelayNoResults = "DesiredState.OPENRELAY.Results.None";
    public const string OpenRelayNotAllowed = "DesiredState.OPENRELAY.AllowsRelay.NotAllowed";
    public const string OpenRelayConnectionFailed = "DesiredState.OPENRELAY.ConnectionFailed.Drift";

    public const string MailLatencyNoResults = "DesiredState.MAILLATENCY.Results.None";
    public const string MailLatencyConnectFailed = "DesiredState.MAILLATENCY.Connect.Required.Failed";
    public const string MailLatencyBannerFailed = "DesiredState.MAILLATENCY.Banner.Required.Failed";
    public const string MailLatencyConnectTooSlow = "DesiredState.MAILLATENCY.Connect.Time.TooHigh";
    public const string MailLatencyBannerTooSlow = "DesiredState.MAILLATENCY.Banner.Time.TooHigh";

    public const string OpenResolverNoResults = "DesiredState.OPENRESOLVER.Results.None";
    public const string OpenResolverNotAllowed = "DesiredState.OPENRESOLVER.Open.NotAllowed";

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

    public const string ReverseDnsNoResults = "DesiredState.REVERSEDNS.Results.None";
    public const string ReverseDnsPtrMissing = "DesiredState.REVERSEDNS.PTR.Missing";
    public const string ReverseDnsPtrExpectedMismatch = "DesiredState.REVERSEDNS.PTR.ExpectedHost.Mismatch";
    public const string ReverseDnsPtrSuffixNotAllowed = "DesiredState.REVERSEDNS.PTR.Suffix.NotAllowed";
    public const string ReverseDnsForwardNotConfirmed = "DesiredState.REVERSEDNS.FCrDNS.Required";

    public const string FcrDnsNoResults = "DesiredState.FCRDNS.Results.None";
    public const string FcrDnsForwardMismatch = "DesiredState.FCRDNS.ForwardConfirmed.Mismatch";

    public const string NsMissingRecord = "DesiredState.NS.Record.Missing";
    public const string NsTooFewRecords = "DesiredState.NS.Records.TooFew";
    public const string NsDuplicatesNotAllowed = "DesiredState.NS.Records.Duplicate.NotAllowed";
    public const string NsMissingAddress = "DesiredState.NS.Target.NoAddress";
    public const string NsCnameTargetNotAllowed = "DesiredState.NS.Target.CNAME.NotAllowed";
    public const string NsDiversityRequired = "DesiredState.NS.Diversity.Required";
    public const string NsAsnDiversityTooLow = "DesiredState.NS.ASN.Diversity.TooLow";
    public const string NsHostNotAllowed = "DesiredState.NS.Host.NotAllowed";

    public const string DanglingCnameDangling = "DesiredState.DANGLINGCNAME.Target.Dangling";
    public const string DanglingCnameUnclaimedService = "DesiredState.DANGLINGCNAME.Target.UnclaimedService";

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

    public const string DnsblNoResults = "DesiredState.DNSBL.Results.None";
    public const string DnsblListed = "DesiredState.DNSBL.Listed";

    public const string DnsHealthNoResults = "DesiredState.DNSHEALTH.Results.None";
    public const string DnsHealthServersUnresponsive = "DesiredState.DNSHEALTH.Servers.NotResponsive";
    public const string DnsHealthSoaSerialInconsistent = "DesiredState.DNSHEALTH.SOA.Serial.Inconsistent";
    public const string DnsHealthApexInconsistent = "DesiredState.DNSHEALTH.Apex.Inconsistent";

    public const string ApexAddressRequiredMissing = "DesiredState.APEXADDRESS.Addresses.Required.Missing";
    public const string ApexAddressNotAllowed = "DesiredState.APEXADDRESS.Addresses.NotAllowed";
    public const string ApexAddressPrivateNotAllowed = "DesiredState.APEXADDRESS.Addresses.Private.NotAllowed";
    public const string ApexAddressLoopbackNotAllowed = "DesiredState.APEXADDRESS.Addresses.Loopback.NotAllowed";
    public const string ApexAddressLinkLocalNotAllowed = "DesiredState.APEXADDRESS.Addresses.LinkLocal.NotAllowed";
    public const string ApexAddressMulticastNotAllowed = "DesiredState.APEXADDRESS.Addresses.Multicast.NotAllowed";
    public const string ApexAddressDocumentationNotAllowed = "DesiredState.APEXADDRESS.Addresses.Documentation.NotAllowed";
    public const string ApexAddressUniqueLocalNotAllowed = "DesiredState.APEXADDRESS.Addresses.UniqueLocalV6.NotAllowed";
    public const string ApexAddressSubnetDiversityTooLowV4 = "DesiredState.APEXADDRESS.SubnetDiversity.V4.TooLow";
    public const string ApexAddressSubnetDiversityTooLowV6 = "DesiredState.APEXADDRESS.SubnetDiversity.V6.TooLow";
    public const string ApexAddressPtrRequiredMissing = "DesiredState.APEXADDRESS.PTR.Required.Missing";
    public const string ApexAddressFcrDnsRequired = "DesiredState.APEXADDRESS.FCrDNS.Required";

    public const string RpkiNoResults = "DesiredState.RPKI.Results.None";
    public const string RpkiQueryFailed = "DesiredState.RPKI.Query.Failed";
    public const string RpkiInvalid = "DesiredState.RPKI.Validity.Invalid";

    public const string EdnsNoResults = "DesiredState.EDNSSUPPORT.Results.None";
    public const string EdnsNotSupported = "DesiredState.EDNSSUPPORT.NotSupported";
    public const string EdnsUdpPayloadTooLarge = "DesiredState.EDNSSUPPORT.UdpPayload.TooLarge";
    public const string EdnsVersionNotAllowed = "DesiredState.EDNSSUPPORT.Version.NotAllowed";
    public const string EdnsCookieNotSupported = "DesiredState.EDNSSUPPORT.Cookie.NotSupported";

    public const string DnsOverTlsNoResults = "DesiredState.DNSOVERTLS.Results.None";
    public const string DnsOverTlsAnySupportedRequired = "DesiredState.DNSOVERTLS.Supported.Any.Required";
    public const string DnsOverTlsAllSupportedRequired = "DesiredState.DNSOVERTLS.Supported.All.Required";
    public const string DnsOverTlsCertificateInvalid = "DesiredState.DNSOVERTLS.Certificate.Invalid";
    public const string DnsOverTlsCertificateMismatch = "DesiredState.DNSOVERTLS.Certificate.Hostname.Mismatch";

    public const string FlatteningServiceCnameRequiredMissing = "DesiredState.FLATTENINGSERVICE.CNAME.Required.Missing";
    public const string FlatteningServiceCnameNotAllowed = "DesiredState.FLATTENINGSERVICE.CNAME.NotAllowed";
    public const string FlatteningServiceRequiredMissing = "DesiredState.FLATTENINGSERVICE.Required.Missing";
    public const string FlatteningServiceNotAllowed = "DesiredState.FLATTENINGSERVICE.NotAllowed";
    public const string FlatteningServiceTargetNotAllowed = "DesiredState.FLATTENINGSERVICE.Target.NotAllowed";

    public const string DelegationMismatch = "DesiredState.DELEGATION.Parent.Mismatch";
    public const string DelegationGlueIncomplete = "DesiredState.DELEGATION.Glue.Incomplete";
    public const string DelegationGlueInconsistent = "DesiredState.DELEGATION.Glue.Inconsistent";

    public const string ZoneTransferAllowed = "DesiredState.ZONETRANSFER.AXFR.Allowed";

    public const string WildcardCatchAllRequired = "DesiredState.WILDCARDDNS.CatchAll.Required";
    public const string WildcardCatchAllNotAllowed = "DesiredState.WILDCARDDNS.CatchAll.NotAllowed";

    public const string TtlAOutOfRange = "DesiredState.TTL.A.OutOfRange";
    public const string TtlAaaaOutOfRange = "DesiredState.TTL.AAAA.OutOfRange";
    public const string TtlMxOutOfRange = "DesiredState.TTL.MX.OutOfRange";
    public const string TtlNsOutOfRange = "DesiredState.TTL.NS.OutOfRange";
    public const string TtlSoaOutOfRange = "DesiredState.TTL.SOA.OutOfRange";
    public const string TtlSpfTxtOutOfRange = "DesiredState.TTL.TXT.SPF.OutOfRange";
    public const string TtlDmarcTxtOutOfRange = "DesiredState.TTL.TXT.DMARC.OutOfRange";
    public const string TtlDkimTxtOutOfRange = "DesiredState.TTL.TXT.DKIM.OutOfRange";
    public const string TtlMtastsTxtOutOfRange = "DesiredState.TTL.TXT.MTASTS.OutOfRange";
    public const string TtlTlsRptTxtOutOfRange = "DesiredState.TTL.TXT.TLSRPT.OutOfRange";

    public const string TtlAUniformityRequired = "DesiredState.TTL.A.Uniformity.Required";
    public const string TtlAaaaUniformityRequired = "DesiredState.TTL.AAAA.Uniformity.Required";
    public const string TtlNsUniformityRequired = "DesiredState.TTL.NS.Uniformity.Required";
    public const string TtlCnameUniformityRequired = "DesiredState.TTL.CNAME.Uniformity.Required";
    public const string TtlSpfTxtUniformityRequired = "DesiredState.TTL.TXT.SPF.Uniformity.Required";
    public const string TtlDmarcTxtUniformityRequired = "DesiredState.TTL.TXT.DMARC.Uniformity.Required";
    public const string TtlDkimTxtUniformityRequired = "DesiredState.TTL.TXT.DKIM.Uniformity.Required";

    public const string AutodiscoverSrvMissingRecord = "DesiredState.AUTODISCOVER.SRV.Record.Missing";
    public const string AutodiscoverSrvTargetNotAllowed = "DesiredState.AUTODISCOVER.SRV.Target.NotAllowed";
    public const string AutodiscoverCnameMissingRecord = "DesiredState.AUTODISCOVER.CNAME.Record.Missing";
    public const string AutodiscoverCnameTargetNotAllowed = "DesiredState.AUTODISCOVER.CNAME.Target.NotAllowed";
    public const string AutoconfigCnameMissingRecord = "DesiredState.AUTODISCOVER.Autoconfig.CNAME.Record.Missing";
    public const string AutoconfigCnameTargetNotAllowed = "DesiredState.AUTODISCOVER.Autoconfig.CNAME.Target.NotAllowed";
    public const string AutodiscoverNoValidEndpoint = "DesiredState.AUTODISCOVER.Endpoint.Valid.Required";
    public const string AutodiscoverValidEndpointHostNotAllowed = "DesiredState.AUTODISCOVER.Endpoint.Host.NotAllowed";

    public const string SecurityTxtMissingRecord = "DesiredState.SECURITYTXT.Record.Missing";
    public const string SecurityTxtInvalidRecord = "DesiredState.SECURITYTXT.Record.Invalid";
    public const string SecurityTxtFallbackNotAllowed = "DesiredState.SECURITYTXT.Fallback.NotAllowed";
    public const string SecurityTxtPgpSignedRequired = "DesiredState.SECURITYTXT.PGP.Required";
    public const string SecurityTxtContactEmailMissing = "DesiredState.SECURITYTXT.Contact.Email.Missing";
    public const string SecurityTxtContactEmailDomainNotAllowed = "DesiredState.SECURITYTXT.Contact.Email.Domain.NotAllowed";

    public const string RobotsMissingRecord = "DesiredState.ROBOTS.Record.Missing";
    public const string RobotsFallbackNotAllowed = "DesiredState.ROBOTS.Fallback.NotAllowed";
    public const string RobotsAiBotRulesRequired = "DesiredState.ROBOTS.AiBots.Required";
    public const string RobotsSitemapRequired = "DesiredState.ROBOTS.Sitemap.Required";
}
