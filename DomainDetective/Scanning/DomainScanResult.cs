using System;
using System.Collections.Generic;

namespace DomainDetective.Scanning;

/// <summary>Aggregate result for a domain scan.</summary>
public sealed class DomainScanResult
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; init; } = string.Empty;
    /// <summary>Gets or sets the started utc value.</summary>
    public DateTime StartedUtc { get; init; } = DateTime.UtcNow;
    /// <summary>Gets or sets the finished utc value.</summary>
    public DateTime FinishedUtc { get; set; }

    /// <summary>Gets or sets the dns value.</summary>
    public DnsResult Dns { get; init; } = new();
    /// <summary>Gets or sets the mail value.</summary>
    public MailResult Mail { get; init; } = new();
    /// <summary>Gets or sets the web value.</summary>
    public WebResult Web { get; init; } = new();
    /// <summary>Gets or sets the reputation value.</summary>
    public ReputationResult Reputation { get; init; } = new();

    /// <summary>Gets the notes value.</summary>
    public List<string> Notes { get; } = new();
}

/// <summary>DNS-related results.</summary>
public sealed class DnsResult
{
    /// <summary>Gets or sets the soa value.</summary>
    public SoaInfo? Soa { get; set; }
    /// <summary>Gets or sets the ns value.</summary>
    public List<string> Ns { get; set; } = new();
    /// <summary>Gets or sets the mx value.</summary>
    public List<MxInfo> Mx { get; set; } = new();
    /// <summary>Gets or sets the dnssec enabled value.</summary>
    public bool? DnssecEnabled { get; set; }
    /// <summary>Gets or sets the zone transfer open value.</summary>
    public bool? ZoneTransferOpen { get; set; }
    /// <summary>Gets or sets the wildcard detected value.</summary>
    public bool? WildcardDetected { get; set; }
    /// <summary>Gets or sets the open resolver value.</summary>
    public bool? OpenResolver { get; set; }
    /// <summary>Gets or sets the min ttl value.</summary>
    public TimeSpan? MinTtl { get; set; }
    /// <summary>Gets or sets the max ttl value.</summary>
    public TimeSpan? MaxTtl { get; set; }
    /// <summary>Gets or sets the reverse value.</summary>
    public List<PtrInfo> Reverse { get; set; } = new();
    /// <summary>Gets or sets the f cr dns aligned value.</summary>
    public bool? FCrDnsAligned { get; set; }
}

/// <summary>Mail-related results.</summary>
public sealed class MailResult
{
    /// <summary>Gets or sets the spf record value.</summary>
    public string? SpfRecord { get; set; }
    /// <summary>Gets or sets the dmarc record value.</summary>
    public string? DmarcRecord { get; set; }
    /// <summary>Gets or sets the dkim selector hint value.</summary>
    public string? DkimSelectorHint { get; set; }
    /// <summary>Gets or sets the dkim selectors ok value.</summary>
    public Dictionary<string, bool?> DkimSelectorsOk { get; set; } = new();
    /// <summary>Gets or sets the bimi record value.</summary>
    public string? BimiRecord { get; set; }
    /// <summary>Gets or sets the mta sts policy value.</summary>
    public string? MtaStsPolicy { get; set; }
    /// <summary>Gets or sets the tls rpt value.</summary>
    public string? TlsRpt { get; set; }

    /// <summary>Gets or sets the smtp start tls ok value.</summary>
    public bool? SmtpStartTlsOk { get; set; }
    /// <summary>Gets or sets the imap tls ok value.</summary>
    public bool? ImapTlsOk { get; set; }
    /// <summary>Gets or sets the pop3 tls ok value.</summary>
    public bool? Pop3TlsOk { get; set; }
    /// <summary>Gets or sets the open relay suspected value.</summary>
    public bool? OpenRelaySuspected { get; set; }

    /// <summary>Gets or sets the policy score value.</summary>
    public MailPolicyScore PolicyScore { get; set; } = new();
}

/// <summary>Web-related results.</summary>
public sealed class WebResult
{
    /// <summary>Gets or sets the http ok value.</summary>
    public bool? HttpOk { get; set; }
    /// <summary>Gets or sets the https ok value.</summary>
    public bool? HttpsOk { get; set; }
    /// <summary>Gets or sets the http2 value.</summary>
    public bool? Http2 { get; set; }
    /// <summary>Gets or sets the http3 value.</summary>
    public bool? Http3 { get; set; }
    /// <summary>Gets or sets the hsts value.</summary>
    public bool? Hsts { get; set; }
    /// <summary>Gets or sets the security headers missing value.</summary>
    public List<string> SecurityHeadersMissing { get; set; } = new();
    /// <summary>Gets or sets the tls value.</summary>
    public TlsChainInfo? Tls { get; set; }
    /// <summary>Gets or sets the dane tlsa value.</summary>
    public bool? DaneTlsa { get; set; }
    /// <summary>Gets or sets the smimea value.</summary>
    public bool? Smimea { get; set; }
}

/// <summary>Reputation and registry-related results.</summary>
public sealed class ReputationResult
{
    /// <summary>Gets or sets the whois registrar value.</summary>
    public string? WhoisRegistrar { get; set; }
    /// <summary>Gets or sets the rdap handle value.</summary>
    public string? RdapHandle { get; set; }
    /// <summary>Gets or sets the rpki valid value.</summary>
    public bool? RpkiValid { get; set; }
    /// <summary>Gets or sets the blacklists value.</summary>
    public List<string> Blacklists { get; set; } = new();
}

// --- Submodels ---
/// <summary>Provides soa info functionality.</summary>
public sealed class SoaInfo
{
    /// <summary>Gets or sets the primary name server value.</summary>
    public string? PrimaryNs { get; set; }

    /// <summary>Gets or sets the responsible mailbox value.</summary>
    public string? RName { get; set; }

    /// <summary>Gets or sets the SOA serial value.</summary>
    public long? Serial { get; set; }
}

/// <summary>Provides mx info functionality.</summary>
public sealed class MxInfo
{
    /// <summary>Gets or sets the mail exchanger host value.</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>Gets or sets the mail exchanger preference value.</summary>
    public int Preference { get; set; }

    /// <summary>Gets or sets whether the mail exchanger resolves.</summary>
    public bool? Resolvable { get; set; }
}

/// <summary>Provides ptr info functionality.</summary>
public sealed class PtrInfo
{
    /// <summary>Gets or sets the IP address value.</summary>
    public string Ip { get; set; } = string.Empty;

    /// <summary>Gets or sets the PTR host value.</summary>
    public string? Ptr { get; set; }
}

/// <summary>Provides tls chain info functionality.</summary>
public sealed class TlsChainInfo
{
    /// <summary>Gets or sets the certificate subject value.</summary>
    public string? Subject { get; set; }

    /// <summary>Gets or sets the certificate issuer value.</summary>
    public string? Issuer { get; set; }

    /// <summary>Gets or sets the certificate expiration value.</summary>
    public DateTimeOffset? NotAfter { get; set; }
}

/// <summary>Simple posture scoring for wizard visualizations.</summary>
public sealed class MailPolicyScore
{
    /// <summary>Gets or sets the spf coverage value.</summary>
    public int SpfCoverage { get; set; }
    /// <summary>Gets or sets the dkim selectors value.</summary>
    public int DkimSelectors { get; set; }
    /// <summary>Gets or sets the dmarc strength value.</summary>
    public int DmarcStrength { get; set; }
    /// <summary>Gets or sets the transport tls posture value.</summary>
    public int TransportTlsPosture { get; set; }
}

