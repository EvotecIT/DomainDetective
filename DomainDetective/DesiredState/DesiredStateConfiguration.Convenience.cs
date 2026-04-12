using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed partial class DesiredStateConfiguration {
    /// <summary>Represents the checks value.</summary>
    [JsonIgnore]
    public HealthCheckType[]? Checks {
        get => Defaults.Checks;
        set => Defaults.Checks = value;
    }

    /// <summary>Represents the assessment policy value.</summary>
    [JsonIgnore]
    public DesiredStateAssessmentPolicy? AssessmentPolicy {
        get => Defaults.AssessmentPolicy;
        set => Defaults.AssessmentPolicy = value;
    }

    /// <summary>Represents the dmarc value.</summary>
    [JsonIgnore]
    public DesiredStateDmarcPolicy? Dmarc {
        get => Defaults.Dmarc;
        set => Defaults.Dmarc = value;
    }

    /// <summary>Represents the spf value.</summary>
    [JsonIgnore]
    public DesiredStateSpfPolicy? Spf {
        get => Defaults.Spf;
        set => Defaults.Spf = value;
    }

    /// <summary>Represents the dkim value.</summary>
    [JsonIgnore]
    public DesiredStateDkimPolicy? Dkim {
        get => Defaults.Dkim;
        set => Defaults.Dkim = value;
    }

    /// <summary>Represents the mtasts value.</summary>
    [JsonIgnore]
    public DesiredStateMtastsPolicy? Mtasts {
        get => Defaults.Mtasts;        
        set => Defaults.Mtasts = value;
    }

    /// <summary>Represents the tls rpt value.</summary>
    [JsonIgnore]
    public DesiredStateTlsRptPolicy? TlsRpt {
        get => Defaults.TlsRpt;        
        set => Defaults.TlsRpt = value;
    }

    /// <summary>Represents the bimi value.</summary>
    [JsonIgnore]
    public DesiredStateBimiPolicy? Bimi {
        get => Defaults.Bimi;
        set => Defaults.Bimi = value;
    }

    /// <summary>Represents the mx value.</summary>
    [JsonIgnore]
    public DesiredStateMxPolicy? Mx {
        get => Defaults.Mx;
        set => Defaults.Mx = value;
    }

    /// <summary>Represents the start tls value.</summary>
    [JsonIgnore]
    public DesiredStateStartTlsPolicy? StartTls {
        get => Defaults.StartTls;    
        set => Defaults.StartTls = value;
    }

    /// <summary>Represents the smtp tls value.</summary>
    [JsonIgnore]
    public DesiredStateMailTlsPolicy? SmtpTls {
        get => Defaults.SmtpTls;      
        set => Defaults.SmtpTls = value;
    }

    /// <summary>Represents the imap tls value.</summary>
    [JsonIgnore]
    public DesiredStateMailTlsPolicy? ImapTls {
        get => Defaults.ImapTls;      
        set => Defaults.ImapTls = value;
    }

    /// <summary>Represents the pop3 tls value.</summary>
    [JsonIgnore]
    public DesiredStateMailTlsPolicy? Pop3Tls {
        get => Defaults.Pop3Tls;      
        set => Defaults.Pop3Tls = value;
    }

    /// <summary>Represents the smtp banner value.</summary>
    [JsonIgnore]
    public DesiredStateSmtpBannerPolicy? SmtpBanner {
        get => Defaults.SmtpBanner;
        set => Defaults.SmtpBanner = value;
    }

    /// <summary>Represents the smtp auth value.</summary>
    [JsonIgnore]
    public DesiredStateSmtpAuthPolicy? SmtpAuth {
        get => Defaults.SmtpAuth;    
        set => Defaults.SmtpAuth = value;
    }

    /// <summary>Represents the open relay value.</summary>
    [JsonIgnore]
    public DesiredStateOpenRelayPolicy? OpenRelay {
        get => Defaults.OpenRelay;  
        set => Defaults.OpenRelay = value;
    }

    /// <summary>Represents the open resolver value.</summary>
    [JsonIgnore]
    public DesiredStateOpenResolverPolicy? OpenResolver {
        get => Defaults.OpenResolver;
        set => Defaults.OpenResolver = value;
    }

    /// <summary>Represents the mail latency value.</summary>
    [JsonIgnore]
    public DesiredStateMailLatencyPolicy? MailLatency {
        get => Defaults.MailLatency;
        set => Defaults.MailLatency = value;
    }

    /// <summary>Represents the reverse dns value.</summary>
    [JsonIgnore]
    public DesiredStateReverseDnsPolicy? ReverseDns {
        get => Defaults.ReverseDns;
        set => Defaults.ReverseDns = value;
    }

    /// <summary>Represents the fcr dns value.</summary>
    [JsonIgnore]
    public DesiredStateFcrDnsPolicy? FcrDns {
        get => Defaults.FcrDns;        
        set => Defaults.FcrDns = value;
    }

    /// <summary>Represents the ns value.</summary>
    [JsonIgnore]
    public DesiredStateNsPolicy? Ns {
        get => Defaults.Ns;
        set => Defaults.Ns = value;
    }

    /// <summary>Represents the dangling cname value.</summary>
    [JsonIgnore]
    public DesiredStateDanglingCnamePolicy? DanglingCname {
        get => Defaults.DanglingCname;
        set => Defaults.DanglingCname = value;
    }

    /// <summary>Represents the caa value.</summary>
    [JsonIgnore]
    public DesiredStateCaaPolicy? Caa {
        get => Defaults.Caa;
        set => Defaults.Caa = value;
    }

    /// <summary>Represents the dns sec value.</summary>
    [JsonIgnore]
    public DesiredStateDnssecPolicy? DnsSec {
        get => Defaults.DnsSec;        
        set => Defaults.DnsSec = value;
    }

    /// <summary>Represents the soa value.</summary>
    [JsonIgnore]
    public DesiredStateSoaPolicy? Soa {
        get => Defaults.Soa;
        set => Defaults.Soa = value;
    }

    /// <summary>Represents the dane value.</summary>
    [JsonIgnore]
    public DesiredStateDanePolicy? Dane {
        get => Defaults.Dane;
        set => Defaults.Dane = value;
    }

    /// <summary>Represents the dnsbl value.</summary>
    [JsonIgnore]
    public DesiredStateDnsblPolicy? Dnsbl {
        get => Defaults.Dnsbl;
        set => Defaults.Dnsbl = value;
    }

    /// <summary>Represents the dns health value.</summary>
    [JsonIgnore]
    public DesiredStateDnsHealthPolicy? DnsHealth {
        get => Defaults.DnsHealth;  
        set => Defaults.DnsHealth = value;
    }

    /// <summary>Represents the apex address value.</summary>
    [JsonIgnore]
    public DesiredStateApexAddressPolicy? ApexAddress {
        get => Defaults.ApexAddress;
        set => Defaults.ApexAddress = value;
    }

    /// <summary>Represents the rpki value.</summary>
    [JsonIgnore]
    public DesiredStateRpkiPolicy? Rpki {
        get => Defaults.Rpki;
        set => Defaults.Rpki = value;
    }

    /// <summary>Represents the edns support value.</summary>
    [JsonIgnore]
    public DesiredStateEdnsSupportPolicy? EdnsSupport {
        get => Defaults.EdnsSupport;
        set => Defaults.EdnsSupport = value;
    }

    /// <summary>Represents the dns over tls value.</summary>
    [JsonIgnore]
    public DesiredStateDnsOverTlsPolicy? DnsOverTls {
        get => Defaults.DnsOverTls;
        set => Defaults.DnsOverTls = value;
    }

    /// <summary>Represents the flattening service value.</summary>
    [JsonIgnore]
    public DesiredStateFlatteningServicePolicy? FlatteningService {       
        get => Defaults.FlatteningService;
        set => Defaults.FlatteningService = value;
    }

    /// <summary>Represents the delegation value.</summary>
    [JsonIgnore]
    public DesiredStateDelegationPolicy? Delegation {
        get => Defaults.Delegation;  
        set => Defaults.Delegation = value;
    }

    /// <summary>Represents the zone transfer value.</summary>
    [JsonIgnore]
    public DesiredStateZoneTransferPolicy? ZoneTransfer {
        get => Defaults.ZoneTransfer;
        set => Defaults.ZoneTransfer = value;
    }

    /// <summary>Represents the wildcard dns value.</summary>
    [JsonIgnore]
    public DesiredStateWildcardDnsPolicy? WildcardDns {
        get => Defaults.WildcardDns;
        set => Defaults.WildcardDns = value;
    }

    /// <summary>Represents the ttl value.</summary>
    [JsonIgnore]
    public DesiredStateTtlPolicy? Ttl {
        get => Defaults.Ttl;
        set => Defaults.Ttl = value;
    }

    /// <summary>Represents the autodiscover value.</summary>
    [JsonIgnore]
    public DesiredStateAutodiscoverPolicy? Autodiscover {
        get => Defaults.Autodiscover;
        set => Defaults.Autodiscover = value;
    }

    /// <summary>Represents the security txt value.</summary>
    [JsonIgnore]
    public DesiredStateSecurityTxtPolicy? SecurityTxt {
        get => Defaults.SecurityTxt;
        set => Defaults.SecurityTxt = value;
    }

    /// <summary>Represents the robots value.</summary>
    [JsonIgnore]
    public DesiredStateRobotsPolicy? Robots {
        get => Defaults.Robots;
        set => Defaults.Robots = value;
    }

    /// <summary>Represents the certificate inventory value.</summary>
    [JsonIgnore]
    public DesiredStateCertificateInventoryPolicy? CertificateInventory {
        get => Defaults.CertificateInventory;
        set => Defaults.CertificateInventory = value;
    }
}
