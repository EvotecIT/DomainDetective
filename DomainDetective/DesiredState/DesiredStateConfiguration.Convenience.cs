using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed partial class DesiredStateConfiguration {
    [JsonIgnore]
    public HealthCheckType[]? Checks {
        get => Defaults.Checks;
        set => Defaults.Checks = value;
    }

    [JsonIgnore]
    public DesiredStateAssessmentPolicy? AssessmentPolicy {
        get => Defaults.AssessmentPolicy ??= new DesiredStateAssessmentPolicy();
        set => Defaults.AssessmentPolicy = value;
    }

    [JsonIgnore]
    public DesiredStateDmarcPolicy? Dmarc {
        get => Defaults.Dmarc ??= new DesiredStateDmarcPolicy();
        set => Defaults.Dmarc = value;
    }

    [JsonIgnore]
    public DesiredStateSpfPolicy? Spf {
        get => Defaults.Spf ??= new DesiredStateSpfPolicy();
        set => Defaults.Spf = value;
    }

    [JsonIgnore]
    public DesiredStateDkimPolicy? Dkim {
        get => Defaults.Dkim ??= new DesiredStateDkimPolicy();
        set => Defaults.Dkim = value;
    }

    [JsonIgnore]
    public DesiredStateMtastsPolicy? Mtasts {
        get => Defaults.Mtasts ??= new DesiredStateMtastsPolicy();
        set => Defaults.Mtasts = value;
    }

    [JsonIgnore]
    public DesiredStateTlsRptPolicy? TlsRpt {
        get => Defaults.TlsRpt ??= new DesiredStateTlsRptPolicy();
        set => Defaults.TlsRpt = value;
    }

    [JsonIgnore]
    public DesiredStateBimiPolicy? Bimi {
        get => Defaults.Bimi ??= new DesiredStateBimiPolicy();
        set => Defaults.Bimi = value;
    }

    [JsonIgnore]
    public DesiredStateMxPolicy? Mx {
        get => Defaults.Mx ??= new DesiredStateMxPolicy();
        set => Defaults.Mx = value;
    }

    [JsonIgnore]
    public DesiredStateStartTlsPolicy? StartTls {
        get => Defaults.StartTls ??= new DesiredStateStartTlsPolicy();
        set => Defaults.StartTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? SmtpTls {
        get => Defaults.SmtpTls ??= new DesiredStateMailTlsPolicy();
        set => Defaults.SmtpTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? ImapTls {
        get => Defaults.ImapTls ??= new DesiredStateMailTlsPolicy();
        set => Defaults.ImapTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? Pop3Tls {
        get => Defaults.Pop3Tls ??= new DesiredStateMailTlsPolicy();
        set => Defaults.Pop3Tls = value;
    }

    [JsonIgnore]
    public DesiredStateSmtpBannerPolicy? SmtpBanner {
        get => Defaults.SmtpBanner ??= new DesiredStateSmtpBannerPolicy();
        set => Defaults.SmtpBanner = value;
    }

    [JsonIgnore]
    public DesiredStateSmtpAuthPolicy? SmtpAuth {
        get => Defaults.SmtpAuth ??= new DesiredStateSmtpAuthPolicy();
        set => Defaults.SmtpAuth = value;
    }

    [JsonIgnore]
    public DesiredStateOpenRelayPolicy? OpenRelay {
        get => Defaults.OpenRelay ??= new DesiredStateOpenRelayPolicy();
        set => Defaults.OpenRelay = value;
    }

    [JsonIgnore]
    public DesiredStateOpenResolverPolicy? OpenResolver {
        get => Defaults.OpenResolver ??= new DesiredStateOpenResolverPolicy();
        set => Defaults.OpenResolver = value;
    }

    [JsonIgnore]
    public DesiredStateMailLatencyPolicy? MailLatency {
        get => Defaults.MailLatency ??= new DesiredStateMailLatencyPolicy();
        set => Defaults.MailLatency = value;
    }

    [JsonIgnore]
    public DesiredStateReverseDnsPolicy? ReverseDns {
        get => Defaults.ReverseDns ??= new DesiredStateReverseDnsPolicy();
        set => Defaults.ReverseDns = value;
    }

    [JsonIgnore]
    public DesiredStateFcrDnsPolicy? FcrDns {
        get => Defaults.FcrDns ??= new DesiredStateFcrDnsPolicy();
        set => Defaults.FcrDns = value;
    }

    [JsonIgnore]
    public DesiredStateNsPolicy? Ns {
        get => Defaults.Ns ??= new DesiredStateNsPolicy();
        set => Defaults.Ns = value;
    }

    [JsonIgnore]
    public DesiredStateDanglingCnamePolicy? DanglingCname {
        get => Defaults.DanglingCname ??= new DesiredStateDanglingCnamePolicy();
        set => Defaults.DanglingCname = value;
    }

    [JsonIgnore]
    public DesiredStateCaaPolicy? Caa {
        get => Defaults.Caa ??= new DesiredStateCaaPolicy();
        set => Defaults.Caa = value;
    }

    [JsonIgnore]
    public DesiredStateDnssecPolicy? DnsSec {
        get => Defaults.DnsSec ??= new DesiredStateDnssecPolicy();
        set => Defaults.DnsSec = value;
    }

    [JsonIgnore]
    public DesiredStateSoaPolicy? Soa {
        get => Defaults.Soa ??= new DesiredStateSoaPolicy();
        set => Defaults.Soa = value;
    }

    [JsonIgnore]
    public DesiredStateDanePolicy? Dane {
        get => Defaults.Dane ??= new DesiredStateDanePolicy();
        set => Defaults.Dane = value;
    }

    [JsonIgnore]
    public DesiredStateDnsblPolicy? Dnsbl {
        get => Defaults.Dnsbl ??= new DesiredStateDnsblPolicy();
        set => Defaults.Dnsbl = value;
    }

    [JsonIgnore]
    public DesiredStateDnsHealthPolicy? DnsHealth {
        get => Defaults.DnsHealth ??= new DesiredStateDnsHealthPolicy();
        set => Defaults.DnsHealth = value;
    }

    [JsonIgnore]
    public DesiredStateApexAddressPolicy? ApexAddress {
        get => Defaults.ApexAddress ??= new DesiredStateApexAddressPolicy();
        set => Defaults.ApexAddress = value;
    }

    [JsonIgnore]
    public DesiredStateRpkiPolicy? Rpki {
        get => Defaults.Rpki ??= new DesiredStateRpkiPolicy();
        set => Defaults.Rpki = value;
    }

    [JsonIgnore]
    public DesiredStateEdnsSupportPolicy? EdnsSupport {
        get => Defaults.EdnsSupport ??= new DesiredStateEdnsSupportPolicy();
        set => Defaults.EdnsSupport = value;
    }

    [JsonIgnore]
    public DesiredStateDnsOverTlsPolicy? DnsOverTls {
        get => Defaults.DnsOverTls ??= new DesiredStateDnsOverTlsPolicy();
        set => Defaults.DnsOverTls = value;
    }

    [JsonIgnore]
    public DesiredStateFlatteningServicePolicy? FlatteningService {
        get => Defaults.FlatteningService ??= new DesiredStateFlatteningServicePolicy();
        set => Defaults.FlatteningService = value;
    }

    [JsonIgnore]
    public DesiredStateDelegationPolicy? Delegation {
        get => Defaults.Delegation ??= new DesiredStateDelegationPolicy();
        set => Defaults.Delegation = value;
    }

    [JsonIgnore]
    public DesiredStateZoneTransferPolicy? ZoneTransfer {
        get => Defaults.ZoneTransfer ??= new DesiredStateZoneTransferPolicy();
        set => Defaults.ZoneTransfer = value;
    }

    [JsonIgnore]
    public DesiredStateWildcardDnsPolicy? WildcardDns {
        get => Defaults.WildcardDns ??= new DesiredStateWildcardDnsPolicy();
        set => Defaults.WildcardDns = value;
    }

    [JsonIgnore]
    public DesiredStateTtlPolicy? Ttl {
        get => Defaults.Ttl ??= new DesiredStateTtlPolicy();
        set => Defaults.Ttl = value;
    }

    [JsonIgnore]
    public DesiredStateAutodiscoverPolicy? Autodiscover {
        get => Defaults.Autodiscover ??= new DesiredStateAutodiscoverPolicy();
        set => Defaults.Autodiscover = value;
    }

    [JsonIgnore]
    public DesiredStateSecurityTxtPolicy? SecurityTxt {
        get => Defaults.SecurityTxt ??= new DesiredStateSecurityTxtPolicy();
        set => Defaults.SecurityTxt = value;
    }

    [JsonIgnore]
    public DesiredStateRobotsPolicy? Robots {
        get => Defaults.Robots ??= new DesiredStateRobotsPolicy();
        set => Defaults.Robots = value;
    }
}
