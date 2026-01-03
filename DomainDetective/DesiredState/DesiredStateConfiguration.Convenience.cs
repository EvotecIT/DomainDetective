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
        get => Defaults.AssessmentPolicy;
        set => Defaults.AssessmentPolicy = value;
    }

    [JsonIgnore]
    public DesiredStateDmarcPolicy? Dmarc {
        get => Defaults.Dmarc;
        set => Defaults.Dmarc = value;
    }

    [JsonIgnore]
    public DesiredStateSpfPolicy? Spf {
        get => Defaults.Spf;
        set => Defaults.Spf = value;
    }

    [JsonIgnore]
    public DesiredStateDkimPolicy? Dkim {
        get => Defaults.Dkim;
        set => Defaults.Dkim = value;
    }

    [JsonIgnore]
    public DesiredStateMtastsPolicy? Mtasts {
        get => Defaults.Mtasts;
        set => Defaults.Mtasts = value;
    }

    [JsonIgnore]
    public DesiredStateTlsRptPolicy? TlsRpt {
        get => Defaults.TlsRpt;
        set => Defaults.TlsRpt = value;
    }

    [JsonIgnore]
    public DesiredStateBimiPolicy? Bimi {
        get => Defaults.Bimi;
        set => Defaults.Bimi = value;
    }

    [JsonIgnore]
    public DesiredStateMxPolicy? Mx {
        get => Defaults.Mx;
        set => Defaults.Mx = value;
    }

    [JsonIgnore]
    public DesiredStateStartTlsPolicy? StartTls {
        get => Defaults.StartTls;
        set => Defaults.StartTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? SmtpTls {
        get => Defaults.SmtpTls;
        set => Defaults.SmtpTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? ImapTls {
        get => Defaults.ImapTls;
        set => Defaults.ImapTls = value;
    }

    [JsonIgnore]
    public DesiredStateMailTlsPolicy? Pop3Tls {
        get => Defaults.Pop3Tls;
        set => Defaults.Pop3Tls = value;
    }

    [JsonIgnore]
    public DesiredStateSmtpBannerPolicy? SmtpBanner {
        get => Defaults.SmtpBanner;
        set => Defaults.SmtpBanner = value;
    }

    [JsonIgnore]
    public DesiredStateSmtpAuthPolicy? SmtpAuth {
        get => Defaults.SmtpAuth;
        set => Defaults.SmtpAuth = value;
    }

    [JsonIgnore]
    public DesiredStateOpenRelayPolicy? OpenRelay {
        get => Defaults.OpenRelay;
        set => Defaults.OpenRelay = value;
    }

    [JsonIgnore]
    public DesiredStateOpenResolverPolicy? OpenResolver {
        get => Defaults.OpenResolver;
        set => Defaults.OpenResolver = value;
    }

    [JsonIgnore]
    public DesiredStateMailLatencyPolicy? MailLatency {
        get => Defaults.MailLatency;
        set => Defaults.MailLatency = value;
    }

    [JsonIgnore]
    public DesiredStateReverseDnsPolicy? ReverseDns {
        get => Defaults.ReverseDns;
        set => Defaults.ReverseDns = value;
    }

    [JsonIgnore]
    public DesiredStateFcrDnsPolicy? FcrDns {
        get => Defaults.FcrDns;
        set => Defaults.FcrDns = value;
    }

    [JsonIgnore]
    public DesiredStateNsPolicy? Ns {
        get => Defaults.Ns;
        set => Defaults.Ns = value;
    }

    [JsonIgnore]
    public DesiredStateDanglingCnamePolicy? DanglingCname {
        get => Defaults.DanglingCname;
        set => Defaults.DanglingCname = value;
    }

    [JsonIgnore]
    public DesiredStateCaaPolicy? Caa {
        get => Defaults.Caa;
        set => Defaults.Caa = value;
    }

    [JsonIgnore]
    public DesiredStateDnssecPolicy? DnsSec {
        get => Defaults.DnsSec;
        set => Defaults.DnsSec = value;
    }

    [JsonIgnore]
    public DesiredStateSoaPolicy? Soa {
        get => Defaults.Soa;
        set => Defaults.Soa = value;
    }

    [JsonIgnore]
    public DesiredStateDanePolicy? Dane {
        get => Defaults.Dane;
        set => Defaults.Dane = value;
    }

    [JsonIgnore]
    public DesiredStateDnsblPolicy? Dnsbl {
        get => Defaults.Dnsbl;
        set => Defaults.Dnsbl = value;
    }

    [JsonIgnore]
    public DesiredStateDnsHealthPolicy? DnsHealth {
        get => Defaults.DnsHealth;
        set => Defaults.DnsHealth = value;
    }

    [JsonIgnore]
    public DesiredStateApexAddressPolicy? ApexAddress {
        get => Defaults.ApexAddress;
        set => Defaults.ApexAddress = value;
    }

    [JsonIgnore]
    public DesiredStateRpkiPolicy? Rpki {
        get => Defaults.Rpki;
        set => Defaults.Rpki = value;
    }

    [JsonIgnore]
    public DesiredStateEdnsSupportPolicy? EdnsSupport {
        get => Defaults.EdnsSupport;
        set => Defaults.EdnsSupport = value;
    }

    [JsonIgnore]
    public DesiredStateDnsOverTlsPolicy? DnsOverTls {
        get => Defaults.DnsOverTls;
        set => Defaults.DnsOverTls = value;
    }

    [JsonIgnore]
    public DesiredStateFlatteningServicePolicy? FlatteningService {
        get => Defaults.FlatteningService;
        set => Defaults.FlatteningService = value;
    }

    [JsonIgnore]
    public DesiredStateDelegationPolicy? Delegation {
        get => Defaults.Delegation;
        set => Defaults.Delegation = value;
    }

    [JsonIgnore]
    public DesiredStateZoneTransferPolicy? ZoneTransfer {
        get => Defaults.ZoneTransfer;
        set => Defaults.ZoneTransfer = value;
    }

    [JsonIgnore]
    public DesiredStateWildcardDnsPolicy? WildcardDns {
        get => Defaults.WildcardDns;
        set => Defaults.WildcardDns = value;
    }

    [JsonIgnore]
    public DesiredStateTtlPolicy? Ttl {
        get => Defaults.Ttl;
        set => Defaults.Ttl = value;
    }

    [JsonIgnore]
    public DesiredStateAutodiscoverPolicy? Autodiscover {
        get => Defaults.Autodiscover;
        set => Defaults.Autodiscover = value;
    }

    [JsonIgnore]
    public DesiredStateSecurityTxtPolicy? SecurityTxt {
        get => Defaults.SecurityTxt;
        set => Defaults.SecurityTxt = value;
    }

    [JsonIgnore]
    public DesiredStateRobotsPolicy? Robots {
        get => Defaults.Robots;
        set => Defaults.Robots = value;
    }
}
