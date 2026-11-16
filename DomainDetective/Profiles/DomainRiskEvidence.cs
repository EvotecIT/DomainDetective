using System;
using System.Collections.Generic;

namespace DomainDetective.Profiles;

/// <summary>
/// The evidence a risk profile is computed from, gathered from the analyses that ran. <see cref="DomainRiskProfileBuilder"/>
/// fills it from a <see cref="DomainHealthCheck"/>; callers with their own data can fill it directly and pass it to
/// <see cref="DomainRiskProfileEvaluator.Evaluate"/>.
/// </summary>
public sealed class DomainRiskEvidence {
    /// <summary>Domain.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Threat feed answers, one per feed.</summary>
    public List<ThreatFeedEvidence> Feeds { get; set; } = new();
    /// <summary>Whether the domain itself was checked against domain blocklists.</summary>
    public EvidenceState DomainBlocklistState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Domain blocklists that list the domain.</summary>
    public List<string> DomainBlocklists { get; set; } = new();
    /// <summary>Whether mail and web host addresses were checked against blocklists.</summary>
    public EvidenceState HostBlocklistState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Hosts or addresses listed on at least one blocklist.</summary>
    public int HostsListed { get; set; }
    /// <summary>Hosts and addresses checked.</summary>
    public int HostsChecked { get; set; }

    /// <summary>Source of the registration data: RDAP or WHOIS.</summary>
    public string RegistrationSource { get; set; } = string.Empty;
    /// <summary>Creation date state.</summary>
    public EvidenceState CreatedState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Creation date.</summary>
    public DateTimeOffset? CreatedUtc { get; set; }
    /// <summary>Expiry date state.</summary>
    public EvidenceState ExpiryState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Expiry date.</summary>
    public DateTimeOffset? ExpiresUtc { get; set; }
    /// <summary>Status code state (RDAP only).</summary>
    public EvidenceState StatusState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Registration status codes, for example <c>clientHold</c>.</summary>
    public List<string> Statuses { get; set; } = new();
    /// <summary>Registrar state.</summary>
    public EvidenceState RegistrarState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Registrar name.</summary>
    public string Registrar { get; set; } = string.Empty;
    /// <summary>Whether the registration uses a privacy service. Shown, never scored.</summary>
    public bool? PrivacyProtected { get; set; }

    /// <summary>Certificate transparency state.</summary>
    public EvidenceState CtState { get; set; } = EvidenceState.NotQueried;
    /// <summary>CT source: <c>ddct-api</c>, <c>crt.sh</c> or <c>certspotter</c>.</summary>
    public string CtSource { get; set; } = string.Empty;
    /// <summary>Earliest CT entry.</summary>
    public DateTimeOffset? CtFirstSeenUtc { get; set; }
    /// <summary>Latest CT entry.</summary>
    public DateTimeOffset? CtLastSeenUtc { get; set; }
    /// <summary>True when the CT answer was capped or one of its queries failed, so the earliest entry may be missing.</summary>
    public bool CtCapped { get; set; }
    /// <summary>Unique certificates per issuer.</summary>
    public Dictionary<string, int> Issuers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Unique certificates seen in CT.</summary>
    public int UniqueCertificates { get; set; }
    /// <summary>Certificates first logged in the last 7 days.</summary>
    public int IssuedLast7Days { get; set; }
    /// <summary>Certificates first logged in the last 30 days.</summary>
    public int IssuedLast30Days { get; set; }

    /// <summary>DNS inventory state.</summary>
    public EvidenceState InventoryState { get; set; } = EvidenceState.NotQueried;
    /// <summary>DNS hosting provider.</summary>
    public string DnsProvider { get; set; } = string.Empty;
    /// <summary>Mail provider.</summary>
    public string MailProvider { get; set; } = string.Empty;
    /// <summary>Name server state.</summary>
    public EvidenceState NameServerState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Authoritative name servers.</summary>
    public List<string> NameServers { get; set; } = new();
    /// <summary>DNSSEC state.</summary>
    public EvidenceState DnssecState { get; set; } = EvidenceState.NotQueried;
    /// <summary>DNSSEC validation result.</summary>
    public DnssecValidationStatus? Dnssec { get; set; }
    /// <summary>Reverse DNS state for mail hosts.</summary>
    public EvidenceState PtrState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Mail host addresses without forward-confirmed reverse DNS.</summary>
    public int MailHostsWithoutFcrDns { get; set; }

    /// <summary>Address enrichment state.</summary>
    public EvidenceState NetworkState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Addresses with network and hosting data.</summary>
    public List<ProfileAddress> Addresses { get; set; } = new();

    /// <summary>Web scan state. The web facet counts only when the scan ran.</summary>
    public EvidenceState WebState { get; set; } = EvidenceState.NotQueried;
    /// <summary>Technologies detected on the website.</summary>
    public List<string> Technologies { get; set; } = new();

    /// <summary>Lookalike domains rated High or Critical, when typosquatting ran. Shown as exposure, never scored.</summary>
    public int? HighRiskLookalikes { get; set; }
}

/// <summary>One threat feed's answer.</summary>
public sealed class ThreatFeedEvidence {
    /// <summary>Stable identifier, for example <c>gsb</c>.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Feed name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Whether it was asked and answered.</summary>
    public EvidenceState State { get; set; } = EvidenceState.NotQueried;
    /// <summary>True when the feed lists the domain.</summary>
    public bool Listed { get; set; }
    /// <summary>Weight inside the reputation facet.</summary>
    public double Weight { get; set; }
    /// <summary>What to do when the feed was not queried.</summary>
    public string Action { get; set; } = string.Empty;
}
