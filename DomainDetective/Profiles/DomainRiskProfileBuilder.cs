using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective.Profiles;

/// <summary>Builds a <see cref="DomainRiskProfile"/> from the analyses a <see cref="DomainHealthCheck"/> ran.</summary>
public static class DomainRiskProfileBuilder {
    /// <summary>Checks whose results the profile reads. A profile is produced when at least one of them ran.</summary>
    public static IReadOnlyList<HealthCheckType> SourceChecks { get; } = new[] {
        HealthCheckType.THREATINTEL, HealthCheckType.RDAP, HealthCheckType.WHOIS, HealthCheckType.CTTIMELINE, HealthCheckType.IPENRICHMENT
    };

    /// <summary>True when the health check ran at least one check the profile is built from.</summary>
    /// <param name="health">Health check.</param>
    public static bool HasEvidence(DomainHealthCheck health) =>
        health != null && SourceChecks.Any(check => health.LastVerifiedChecks.Contains(check));

    /// <summary>Builds the profile.</summary>
    /// <param name="health">Health check that ran.</param>
    /// <param name="nowUtc">Evaluation time; defaults to now.</param>
    public static DomainRiskProfile Build(DomainHealthCheck health, DateTimeOffset? nowUtc = null) =>
        DomainRiskProfileEvaluator.Evaluate(CollectEvidence(health), nowUtc);

    /// <summary>Gathers the evidence the profile is computed from.</summary>
    /// <param name="health">Health check that ran.</param>
    public static DomainRiskEvidence CollectEvidence(DomainHealthCheck health) {
        if (health == null) throw new ArgumentNullException(nameof(health));
        var evidence = new DomainRiskEvidence { Domain = health.VerificationDomain ?? string.Empty };
        Reputation(health, evidence);
        Registration(health, evidence);
        Certificates(health, evidence);
        Dns(health, evidence);
        Network(health, evidence);
        Web(health, evidence);
        if (Ran(health, HealthCheckType.TYPOSQUATTING) && !Failed(health, HealthCheckType.TYPOSQUATTING)) {
            evidence.HighRiskLookalikes = health.TyposquattingAnalysis.Candidates.Count(static c =>
                c.RiskLevel is TyposquattingRiskLevel.High or TyposquattingRiskLevel.Critical);
        }
        return evidence;
    }

    private static bool ScannedDomain(string? scanned, string domain) {
        if (string.IsNullOrWhiteSpace(scanned) || string.IsNullOrWhiteSpace(domain)) return false;
        string a = scanned!.Trim().TrimEnd('.'), b = domain.Trim().TrimEnd('.');
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase)
               || b.EndsWith("." + a, StringComparison.OrdinalIgnoreCase)
               || a.EndsWith("." + b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool Ran(DomainHealthCheck health, HealthCheckType check) => health.LastVerifiedChecks.Contains(check);

    private static bool Failed(DomainHealthCheck health, HealthCheckType check) =>
        health.GetCheckFailure(check) is { } failure && failure.Code != "Verification.Check.NotRun";

    private static EvidenceState NotAnswered(DomainHealthCheck health, HealthCheckType check) =>
        !Ran(health, check) ? EvidenceState.NotQueried : EvidenceState.Failed;

    private static readonly (ThreatIntelSource Source, string Id, string Name, double Weight, string Action)[] FeedDefinitions = {
        (ThreatIntelSource.GoogleSafeBrowsing, "gsb", "Google Safe Browsing", 0.25, "Add a Google Safe Browsing API key"),
        (ThreatIntelSource.VirusTotal, "virustotal", "VirusTotal", 0.20, "Add a VirusTotal API key"),
        (ThreatIntelSource.PhishTank, "phishtank", "PhishTank", 0.10, "Add a PhishTank API key"),
        (ThreatIntelSource.UrlHaus, "urlhaus", "URLhaus", 0.10, "Enable URLhaus in threat intel"),
        (ThreatIntelSource.OpenPhish, "openphish", "OpenPhish", 0.10, "Enable OpenPhish in threat intel")
    };

    private static void Reputation(DomainHealthCheck health, DomainRiskEvidence evidence) {
        bool threatRan = Ran(health, HealthCheckType.THREATINTEL);
        bool threatFailed = threatRan && Failed(health, HealthCheckType.THREATINTEL);
        List<ThreatIntelFinding> listings = threatRan && !threatFailed ? health.ThreatIntelAnalysis.Listings.ToList() : new List<ThreatIntelFinding>();
        foreach (var feed in FeedDefinitions) {
            EvidenceState state;
            bool listed = false;
            if (!threatRan) {
                state = EvidenceState.NotQueried;
            } else if (threatFailed) {
                state = EvidenceState.Failed;
            } else {
                ThreatIntelFinding? finding = listings.Where(l => l.Source == feed.Source).Select(static l => (ThreatIntelFinding?)l).FirstOrDefault();
                state = FeedState(finding?.State);
                listed = finding?.State == ThreatIntelQueryState.Listed;
            }
            evidence.Feeds.Add(new ThreatFeedEvidence {
                Id = feed.Id, Name = feed.Name, Weight = feed.Weight, State = state, Listed = listed,
                Action = threatRan ? feed.Action : "Include the threat intel check (" + feed.Name + ")"
            });
        }

        if (!Ran(health, HealthCheckType.DNSBL) || Failed(health, HealthCheckType.DNSBL) || health.DNSBLAnalysis == null) {
            evidence.DomainBlocklistState = evidence.HostBlocklistState = NotAnswered(health, HealthCheckType.DNSBL);
            return;
        }
        List<DNSBLRecord> records = health.DNSBLAnalysis.AllResults ?? new List<DNSBLRecord>();
        List<DNSBLRecord> domainRecords = records.Where(static r => r.QueryKind == DnsblQueryKind.Domain).ToList();
        List<DNSBLRecord> hostRecords = records.Where(static r => r.QueryKind != DnsblQueryKind.Domain).ToList();
        evidence.DomainBlocklistState = BlocklistState(domainRecords);
        evidence.DomainBlocklists = domainRecords.Where(static r => r.IsBlackListed).Select(static r => r.BlackList).Where(static n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        evidence.HostBlocklistState = BlocklistState(hostRecords);
        evidence.HostsChecked = hostRecords.Select(static r => r.IpAddress).Where(static ip => !string.IsNullOrWhiteSpace(ip)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        evidence.HostsListed = hostRecords.Where(static r => r.IsBlackListed).Select(static r => r.IpAddress).Where(static ip => !string.IsNullOrWhiteSpace(ip)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        // Hosts that could not be discovered were never checked, so host coverage is partial however the lists answered.
        evidence.HostBlocklistState = EvidenceCoverage.Limit(evidence.HostBlocklistState, !health.DNSBLAnalysis.DiscoverySucceeded);
    }

    // ---- Per-source mapping onto the shared coverage rule (EvidenceCoverage) --------------------------------------------

    /// <summary>One threat feed: a single query that either answered (listed or clean), failed, or was not asked.</summary>
    internal static EvidenceState FeedState(ThreatIntelQueryState? state) => state switch {
        ThreatIntelQueryState.Listed => EvidenceCoverage.From(1, 1, found: true),
        ThreatIntelQueryState.Clean => EvidenceCoverage.From(1, 1, found: false),
        ThreatIntelQueryState.Failed => EvidenceCoverage.From(1, 0, found: false),
        _ => EvidenceState.NotQueried
    };

    /// <summary>DNSBL lists for the domain or its hosts: every list must answer before the coverage is complete.</summary>
    internal static EvidenceState BlocklistState(IReadOnlyCollection<DNSBLRecord> records) =>
        EvidenceCoverage.From(records.Count, records.Count(static r => r.QuerySucceeded), records.Any(static r => r.QuerySucceeded && r.IsBlackListed));

    /// <summary>CT timeline: an answer that was capped or partly failed is partial history.</summary>
    internal static EvidenceState CtState(bool querySucceeded, bool capped) =>
        EvidenceCoverage.From(1, querySucceeded ? 1 : 0, found: true, capped: capped);

    /// <summary>DNS inventory: every record type queried must answer.</summary>
    internal static EvidenceState InventoryState(bool querySucceeded, int typesQueried, int typesFailed) =>
        !querySucceeded ? EvidenceState.Failed : EvidenceCoverage.From(System.Math.Max(1, typesQueried), System.Math.Max(1, typesQueried) - typesFailed, found: true);

    /// <summary>IP enrichment: a capped address list is partial; per-address completeness is judged by the evaluator.</summary>
    internal static EvidenceState NetworkState(bool querySucceeded, bool capped) =>
        EvidenceCoverage.From(1, querySucceeded ? 1 : 0, found: true, capped: capped);

    /// <summary>Web scan: a scan that did not finish is partial.</summary>
    internal static EvidenceState WebState(bool complete) => EvidenceCoverage.From(1, 1, found: true, capped: !complete);

    private static void Registration(DomainHealthCheck health, DomainRiskEvidence evidence) {
        bool rdapOk = Ran(health, HealthCheckType.RDAP) && !Failed(health, HealthCheckType.RDAP) && health.RdapAnalysis != null &&
                      (health.RdapAnalysis.DomainData != null || !string.IsNullOrWhiteSpace(health.RdapAnalysis.CreationDate));
        bool whoisOk = Ran(health, HealthCheckType.WHOIS) && !Failed(health, HealthCheckType.WHOIS) && health.WhoisAnalysis != null &&
                       (!string.IsNullOrWhiteSpace(health.WhoisAnalysis.CreationDate) || !string.IsNullOrWhiteSpace(health.WhoisAnalysis.Registrar) ||
                        !string.IsNullOrWhiteSpace(health.WhoisAnalysis.ExpiryDate));
        EvidenceState missing = !Ran(health, HealthCheckType.RDAP) && !Ran(health, HealthCheckType.WHOIS) ? EvidenceState.NotQueried : EvidenceState.Failed;

        string? created = rdapOk ? health.RdapAnalysis!.CreationDate : null;
        string createdSource = "RDAP";
        if (string.IsNullOrWhiteSpace(created) && whoisOk) {
            created = health.WhoisAnalysis!.CreationDate;
            createdSource = "WHOIS";
        }
        string? expires = rdapOk && !string.IsNullOrWhiteSpace(health.RdapAnalysis!.ExpiryDate) ? health.RdapAnalysis!.ExpiryDate : whoisOk ? health.WhoisAnalysis!.ExpiryDate : null;
        string? registrar = rdapOk && !string.IsNullOrWhiteSpace(health.RdapAnalysis!.Registrar) ? health.RdapAnalysis!.Registrar : whoisOk ? health.WhoisAnalysis!.Registrar : null;

        evidence.RegistrationSource = rdapOk || whoisOk ? createdSource : string.Empty;
        (evidence.CreatedState, evidence.CreatedUtc) = DateEvidence(created, rdapOk || whoisOk, missing);
        (evidence.ExpiryState, evidence.ExpiresUtc) = DateEvidence(expires, rdapOk || whoisOk, missing);
        evidence.Registrar = registrar?.Trim() ?? string.Empty;
        evidence.RegistrarState = evidence.Registrar.Length > 0 ? EvidenceState.Observed : rdapOk || whoisOk ? EvidenceState.Partial : missing;
        if (rdapOk) {
            evidence.Statuses = health.RdapAnalysis!.Status.Select(static s => StatusName(s.ToString())).ToList();
            evidence.StatusState = EvidenceState.Observed;
        } else {
            evidence.StatusState = NotAnswered(health, HealthCheckType.RDAP);
        }
        if (whoisOk) evidence.PrivacyProtected = health.WhoisAnalysis!.PrivacyProtected;
    }

    private static string StatusName(string value) => value.Length == 0 ? value : char.ToLowerInvariant(value[0]) + value.Substring(1);

    /// <summary>DNSSEC: a definite answer is complete, an indeterminate one partial, anything else a failed check.</summary>
    internal static EvidenceState DnssecState(DnssecValidationStatus status) => status switch {
        DnssecValidationStatus.Secure or DnssecValidationStatus.Insecure or DnssecValidationStatus.Bogus => EvidenceCoverage.From(1, 1, found: true),
        DnssecValidationStatus.Indeterminate => EvidenceCoverage.From(1, 1, found: true, capped: true),
        _ => EvidenceCoverage.From(1, 0, found: false)
    };

    /// <summary>A registration date: parsed is complete, present but unreadable is partial, no answer is failed.</summary>
    internal static (EvidenceState, DateTimeOffset?) DateEvidence(string? text, bool answered, EvidenceState missing) {
        if (!answered) return (missing, null);
        if (string.IsNullOrWhiteSpace(text)) return (EvidenceState.Partial, null);
        if (AmbiguousDayMonth(text!)) return (EvidenceState.Partial, null);
        return TryParseDate(text!, out DateTimeOffset value) ? (EvidenceState.Observed, value) : (EvidenceState.Partial, null);
    }

    // 05/11/2026 is 5 November in one registry and 11 May in another: read it, but don't date the domain by it.
    private static bool AmbiguousDayMonth(string text) {
        System.Text.RegularExpressions.Match m = System.Text.RegularExpressions.Regex.Match(text.Trim(), @"^([0-9]{1,2})/([0-9]{1,2})/[0-9]{4}\b");
        if (!m.Success) return false;
        int first = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), second = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        return first <= 12 && second <= 12 && first != second;
    }

    private static readonly string[] DateFormats = {
        "yyyy-MM-dd", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-dd HH:mm:ss", "yyyy.MM.dd", "yyyy.MM.dd HH:mm:ss", "dd.MM.yyyy", "dd.MM.yyyy HH:mm:ss",
        "dd-MMM-yyyy", "dd-MMM-yyyy HH:mm:ss", "d-MMM-yyyy", "yyyy/MM/dd", "yyyyMMdd", "dd/MM/yyyy", "MMMM d yyyy", "d MMMM yyyy"
    };

    /// <summary>Parses a registration date as RDAP and the common WHOIS servers write it.</summary>
    /// <param name="text">Date text.</param>
    /// <param name="value">Parsed value in UTC.</param>
    public static bool TryParseDate(string text, out DateTimeOffset value) {
        string trimmed = text.Trim();
        int space = trimmed.IndexOf(" (", StringComparison.Ordinal);
        if (space > 0) trimmed = trimmed.Substring(0, space);
        const DateTimeStyles styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal | DateTimeStyles.AllowWhiteSpaces;
        if (DateTimeOffset.TryParseExact(trimmed, DateFormats, CultureInfo.InvariantCulture, styles, out value)) return true;
        return DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, styles, out value);
    }

    private static void Certificates(DomainHealthCheck health, DomainRiskEvidence evidence) {
        CertificateTransparencyTimelineAnalysis? ct = health.CtTimelineAnalysis;
        if (!Ran(health, HealthCheckType.CTTIMELINE) || Failed(health, HealthCheckType.CTTIMELINE) || ct == null) {
            evidence.CtState = NotAnswered(health, HealthCheckType.CTTIMELINE);
            return;
        }
        // A capped answer and a partly failed one both leave out part of the history.
        evidence.CtCapped = ct.ResultsCapped || ct.PartialResults;
        evidence.CtState = CtState(ct.QuerySucceeded, evidence.CtCapped);
        evidence.CtSource = ct.Source;
        evidence.CtFirstSeenUtc = ct.FirstSeenUtc;
        evidence.CtLastSeenUtc = ct.LastSeenUtc;
        evidence.UniqueCertificates = ct.UniqueCertificateCount;
        evidence.IssuedLast7Days = ct.IssuedLast7Days;
        evidence.IssuedLast30Days = ct.IssuedLast30Days;
        evidence.UndatedCertificates = ct.UndatedCertificateCount;
        foreach (var issuer in ct.IssuerCounts) evidence.Issuers[issuer.Key] = issuer.Value;
    }

    private static void Dns(DomainHealthCheck health, DomainRiskEvidence evidence) {
        DnsInventoryAnalysis? inventory = health.DnsInventoryAnalysis;
        if (Ran(health, HealthCheckType.DNSINVENTORY) && !Failed(health, HealthCheckType.DNSINVENTORY) && inventory != null) {
            evidence.InventoryState = InventoryState(inventory.QuerySucceeded, inventory.RecordTypesQueried, inventory.RecordTypesFailed);
            if (inventory.Provider != DnsProvider.Unknown) evidence.DnsProvider = inventory.Provider.ToString();
            if (inventory.MailProvider != MailProviderKind.Unknown) evidence.MailProvider = inventory.MailProvider.ToString();
        } else {
            evidence.InventoryState = NotAnswered(health, HealthCheckType.DNSINVENTORY);
        }

        if (Ran(health, HealthCheckType.NS) && !Failed(health, HealthCheckType.NS) && health.NSAnalysis != null) {
            evidence.NameServers = health.NSAnalysis.NsRecords.Select(static n => n.TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            evidence.NameServerState = evidence.NameServers.Count > 0 ? EvidenceState.Observed : EvidenceState.Partial;
        } else {
            evidence.NameServerState = NotAnswered(health, HealthCheckType.NS);
        }

        if (Ran(health, HealthCheckType.DNSSEC) && !Failed(health, HealthCheckType.DNSSEC) && health.DnsSecAnalysis != null) {
            DnssecValidationStatus status = health.DnsSecAnalysis.ValidationStatus;
            evidence.Dnssec = status;
            evidence.DnssecState = DnssecState(status);
        } else {
            evidence.DnssecState = NotAnswered(health, HealthCheckType.DNSSEC);
        }

        if (Ran(health, HealthCheckType.FCRDNS) && !Failed(health, HealthCheckType.FCRDNS) && health.FcrDnsAnalysis != null) {
            var fcrdns = health.FcrDnsAnalysis.Results;
            // A failed PTR lookup, or a PTR name whose forward lookup returned nothing, may be a lookup failure rather than
            // a defect: it lowers coverage. Only a conclusive missing PTR or a forward answer that misses the address
            // counts against the domain.
            int settled = fcrdns.Count(SettledPtr);
            evidence.PtrState = fcrdns.Count == 0 ? EvidenceState.Clean : EvidenceCoverage.From(fcrdns.Count, settled, found: true);
            evidence.MailHostsWithoutFcrDns = fcrdns.Count(static r => !r.ForwardConfirmed && SettledPtr(r));
        } else {
            evidence.PtrState = NotAnswered(health, HealthCheckType.FCRDNS);
        }
    }

    private static bool SettledPtr(FCrDnsAnalysis.FCrDnsResult result) =>
        result.ForwardAnswered || result.PtrRecords.Count == 0 && !result.PtrLookupFailed;

    private static void Network(DomainHealthCheck health, DomainRiskEvidence evidence) {
        IpEnrichmentAnalysis? enrichment = health.IpEnrichmentAnalysis;
        if (!Ran(health, HealthCheckType.IPENRICHMENT) || Failed(health, HealthCheckType.IPENRICHMENT) || enrichment == null ||
            string.IsNullOrWhiteSpace(enrichment.Subject)) {
            evidence.NetworkState = NotAnswered(health, HealthCheckType.IPENRICHMENT);
            return;
        }
        // When enrichment stopped at its address or host limit, the addresses it dropped were never looked at.
        evidence.NetworkState = NetworkState(enrichment.QuerySucceeded, enrichment.ResultsCapped || enrichment.HostsCapped);
        foreach (IpEnrichmentRow row in enrichment.Rows ?? Array.Empty<IpEnrichmentRow>()) {
            if (evidence.Addresses.Any(a => string.Equals(a.IpAddress, row.IpAddress, StringComparison.OrdinalIgnoreCase))) continue;
            evidence.Addresses.Add(new ProfileAddress {
                IpAddress = row.IpAddress,
                SourceKind = row.SourceKind.ToString(),
                SourceHost = row.SourceHost,
                Asn = row.Asn,
                AsName = row.AsName,
                Cidr = row.Cidr,
                Country = row.Country,
                CountrySource = row.CountrySource,
                HostingProvider = row.HostingAttribution?.Provider ?? string.Empty,
                HostingService = row.HostingAttribution == null ? string.Empty
                    : string.Join(" ", new[] { row.HostingAttribution.Service, row.HostingAttribution.Region }.Where(static v => v.Length > 0)),
                HostingMatchedBy = row.HostingAttribution?.MatchedBy ?? string.Empty,
                IsCdn = row.HostingAttribution?.Kind == DomainDetective.Providers.Hosting.HostingKind.Cdn
            });
        }
    }

    private static void Web(DomainHealthCheck health, DomainRiskEvidence evidence) {
        WebStaticScanAnalysis? web = health.WebStaticScanAnalysis;
        // The web scan is kept across runs, so it counts only when it scanned this domain (or its registrable domain).
        if (web == null || (!web.AnalysisComplete && web.TechDetections.Count == 0 && web.Hosts.Count == 0)
            || !ScannedDomain(web.PrimaryRegistrableDomain, evidence.Domain)) {
            evidence.WebState = EvidenceState.NotQueried;
            return;
        }
        evidence.WebState = WebState(web.AnalysisComplete);
        evidence.Technologies = web.TechDetections.OrderBy(static t => t, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
