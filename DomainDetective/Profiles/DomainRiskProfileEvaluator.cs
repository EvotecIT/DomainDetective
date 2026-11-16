using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Profiles;

/// <summary>
/// Turns <see cref="DomainRiskEvidence"/> into a <see cref="DomainRiskProfile"/>.
/// <para>
/// The risk score adds points for observed signals, capped per facet so one facet can't carry the score alone.
/// Trust signals can lower the total by at most 20, and a live listing on a phishing or malware feed holds the level at
/// High. Evidence that was not queried or failed adds no points; it lowers confidence instead.
/// </para>
/// <para>
/// Confidence is the weighted share of the evidence that came back (observed or clean). When the level depends on one
/// source alone, confidence is capped at Medium; when it holds without any single source, it gets a 0.10 bonus. Below
/// 0.25 the profile is not rated.
/// </para>
/// </summary>
public static class DomainRiskProfileEvaluator {
    /// <summary>Version of the rules below. Scores compare only within one version.</summary>
    public const string RuleVersion = "2026.11";

    /// <summary>Below this evidence score the profile gives no level.</summary>
    public const double RatingFloor = 0.25;

    private const double SingleSourceCap = 0.74;
    private const double CorroborationBonus = 0.10;
    private const int TrustLimit = 20;
    private const int DecisiveFloor = 55;

    private static readonly Dictionary<ProfileFacetKind, int> Caps = new() {
        [ProfileFacetKind.Reputation] = 60,
        [ProfileFacetKind.Registration] = 30,
        [ProfileFacetKind.Certificates] = 20,
        [ProfileFacetKind.Dns] = 15,
        [ProfileFacetKind.Network] = 10,
        [ProfileFacetKind.Web] = 15,
        [ProfileFacetKind.History] = 15
    };

    /// <summary>Evaluates a profile.</summary>
    /// <param name="evidence">Evidence gathered for the domain.</param>
    /// <param name="nowUtc">Evaluation time; defaults to now. Ages are measured from it.</param>
    /// <returns>The profile.</returns>
    public static DomainRiskProfile Evaluate(DomainRiskEvidence evidence, DateTimeOffset? nowUtc = null) {
        if (evidence == null) throw new ArgumentNullException(nameof(evidence));
        DateTimeOffset now = nowUtc ?? DateTimeOffset.UtcNow;

        List<RiskSignal> signals = Signals(evidence, now, null);

        var facets = new List<ProfileFacet> {
            ReputationFacet(evidence),
            RegistrationFacet(evidence, now),
            CertificateFacet(evidence, now),
            DnsFacet(evidence),
            NetworkFacet(evidence),
            WebFacet(evidence),
            HistoryFacet()
        };

        int score = Score(signals, facets);
        DomainRiskLevel level = Level(score, signals.Any(static s => s.Decisive));
        if (signals.Any(static s => s.Decisive)) score = Math.Max(score, DecisiveFloor);

        string? restsOn = null;
        bool corroborated = false;
        if (level >= DomainRiskLevel.Medium) {
            string[] sources = signals.Where(static s => s.Points > 0).Select(static s => s.Source).Distinct(StringComparer.Ordinal).ToArray();
            foreach (string source in sources) {
                // Rebuild without the source, so the next listing takes over as the leading one.
                List<RiskSignal> rest = Signals(evidence, now, source);
                DomainRiskLevel without = Level(Score(rest, null), rest.Any(static s => s.Decisive));
                if (without < level) {
                    restsOn = source;
                    break;
                }
            }
            corroborated = restsOn == null && sources.Length > 1;
        }

        double totalWeight = facets.Where(static f => f.Counted).Sum(static f => f.Weight);
        double evidenceScore = totalWeight <= 0 ? 0 : facets.Where(static f => f.Counted).Sum(static f => f.Weight * f.Coverage) / totalWeight;
        evidenceScore = Round(evidenceScore);
        double confidence = evidenceScore;
        if (restsOn != null) confidence = Math.Min(confidence, SingleSourceCap);
        else if (corroborated) confidence = Math.Min(1, confidence + CorroborationBonus);
        confidence = Round(confidence);

        var profile = new DomainRiskProfile {
            Domain = evidence.Domain,
            EvaluatedAtUtc = now,
            RuleVersion = RuleVersion,
            RiskScore = score,
            RiskLevel = level,
            Rated = evidenceScore >= RatingFloor,
            EvidenceScore = evidenceScore,
            ConfidenceScore = confidence,
            Confidence = confidence >= 0.75 ? EvidenceConfidence.High : confidence >= 0.5 ? EvidenceConfidence.Medium : EvidenceConfidence.Low,
            RestsOn = restsOn,
            Corroborated = corroborated,
            Signals = signals.OrderByDescending(static s => s.Points).ThenBy(static s => s.Id, StringComparer.Ordinal).ToList(),
            Facets = facets,
            Gaps = Gaps(facets, totalWeight),
            Addresses = evidence.Addresses.ToList(),
            Technologies = evidence.Technologies.ToList(),
            CertificateIssuers = evidence.Issuers.OrderByDescending(static i => i.Value).ThenBy(static i => i.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static i => IssuerName(i.Key)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            CtFirstSeenUtc = evidence.CtFirstSeenUtc,
            CtSource = evidence.CtSource,
            RegisteredUtc = evidence.CreatedUtc,
            Registrar = evidence.Registrar
        };
        if (evidence.HighRiskLookalikes is > 0) {
            profile.Watch.Add(evidence.HighRiskLookalikes.Value == 1
                ? "1 lookalike domain rated high risk imitates this domain"
                : evidence.HighRiskLookalikes.Value.ToString(CultureInfo.InvariantCulture) + " lookalike domains rated high risk imitate this domain");
        }
        return profile;
    }

    /// <summary>Level for a score: 75 Critical, 55 High, 30 Medium, above 0 Low. A decisive signal holds it at High.</summary>
    /// <param name="score">Risk score.</param>
    /// <param name="decisive">True when a decisive signal is present.</param>
    public static DomainRiskLevel Level(int score, bool decisive) {
        DomainRiskLevel level = score >= 75 ? DomainRiskLevel.Critical
            : score >= 55 ? DomainRiskLevel.High
            : score >= 30 ? DomainRiskLevel.Medium
            : score > 0 ? DomainRiskLevel.Low
            : DomainRiskLevel.None;
        return decisive && level < DomainRiskLevel.High ? DomainRiskLevel.High : level;
    }

    private static int Score(List<RiskSignal> signals, List<ProfileFacet>? facets) {
        int total = 0;
        int trust = 0;
        foreach (IGrouping<ProfileFacetKind, RiskSignal> group in signals.GroupBy(static s => s.Facet)) {
            int positive = Math.Min(Caps[group.Key], group.Where(static s => s.Points > 0).Sum(static s => s.Points));
            int negative = group.Where(static s => s.Points < 0).Sum(static s => s.Points);
            total += positive;
            trust += negative;
            ProfileFacet? facet = facets?.FirstOrDefault(f => f.Kind == group.Key);
            if (facet != null) facet.RiskPoints = positive + negative;
        }
        total += Math.Max(-TrustLimit, trust);
        return Math.Max(0, Math.Min(100, total));
    }

    private static double Value(EvidenceState state) => state switch {
        EvidenceState.Observed => 1,
        EvidenceState.Clean => 1,
        EvidenceState.Partial => 0.5,
        _ => 0
    };

    private static double Round(double value) => Math.Round(value, 2, MidpointRounding.AwayFromZero);

    private static ProfileFacet Facet(ProfileFacetKind kind, bool core, bool counted, double weight, List<EvidenceItem> items, List<ProfileFact> facts) {
        double itemWeight = items.Sum(static i => i.Weight);
        return new ProfileFacet {
            Kind = kind,
            Core = core,
            Counted = counted,
            Weight = weight,
            Coverage = itemWeight <= 0 ? 0 : Round(items.Sum(static i => i.Weight * Value(i.State)) / itemWeight),
            Evidence = items,
            Facts = facts
        };
    }

    private static EvidenceItem Item(string id, string label, EvidenceState state, double weight, string source, string? check, string? note = null) =>
        new() { Id = id, Label = label, State = state, Weight = weight, Source = source, CheckKey = check, Note = note };

    private static void AddFact(List<ProfileFact> facts, string label, string? value, string? note = null) {
        if (!string.IsNullOrWhiteSpace(value)) facts.Add(new ProfileFact { Label = label, Value = value!.Trim(), Note = note });
    }

    private static string Days(double days) {
        int value = Math.Max(0, (int)Math.Floor(days));
        return value == 1 ? "1 day" : value.ToString(CultureInfo.InvariantCulture) + " days";
    }

    private static string Age(double days) {
        if (days < 365) return Days(days);
        int years = (int)Math.Floor(days / 365.25);
        return years == 1 ? "1 year" : years.ToString(CultureInfo.InvariantCulture) + " years";
    }

    /// <summary>Issuer organisation from a distinguished name ("Let's Encrypt"), else its CN, else the text as given.</summary>
    internal static string IssuerName(string issuer) {
        string? common = null;
        foreach (string part in issuer.Split(',')) {
            string trimmed = part.Trim();
            if (trimmed.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) return TrimCompanySuffix(trimmed.Substring(2).Trim().Trim('"'));
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) common = trimmed.Substring(3).Trim();
        }
        return common ?? issuer.Trim();
    }

    private static string TrimCompanySuffix(string name) {
        foreach (string suffix in new[] { " LLC", " Inc.", " Inc", " Ltd.", " Ltd", " Limited", " GmbH", " S.A.", " B.V.", " Corporation", " Corp." }) {
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return name.Substring(0, name.Length - suffix.Length).TrimEnd(',', ' ');
        }
        return name;
    }

    private static string Date(DateTimeOffset? value) => value?.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? string.Empty;

    // ---- Reputation -------------------------------------------------------------------------------------------------

    private static List<RiskSignal> Signals(DomainRiskEvidence evidence, DateTimeOffset now, string? withoutSource) {
        var signals = new List<RiskSignal>();
        ReputationSignals(evidence, signals, withoutSource);
        RegistrationSignals(evidence, now, signals);
        CertificateSignals(evidence, now, signals);
        DnsSignals(evidence, signals);
        return withoutSource == null
            ? signals
            : signals.Where(s => !string.Equals(s.Source, withoutSource, StringComparison.Ordinal)).ToList();
    }

    private static void ReputationSignals(DomainRiskEvidence e, List<RiskSignal> signals, string? withoutSource) {
        bool first = true;
        foreach (ThreatFeedEvidence feed in e.Feeds.Where(f => f.Listed && f.State == EvidenceState.Observed && !string.Equals(f.Name, withoutSource, StringComparison.Ordinal))
                     .OrderByDescending(static f => f.Weight)) {
            signals.Add(new RiskSignal {
                Id = "reputation.listed." + feed.Id,
                Facet = ProfileFacetKind.Reputation,
                Points = first ? 40 : 10,
                Decisive = first,
                Reason = "Listed by " + feed.Name,
                Source = feed.Name,
                CheckKey = "threatintel"
            });
            first = false;
        }
        if (e.DomainBlocklistState == EvidenceState.Observed && e.DomainBlocklists.Count > 0) {
            signals.Add(new RiskSignal {
                Id = "reputation.domain-blocklist",
                Facet = ProfileFacetKind.Reputation,
                Points = 20,
                Reason = "Domain listed on " + string.Join(", ", e.DomainBlocklists.Take(3)),
                Source = "DNSBL",
                CheckKey = "dnsbl"
            });
        }
        if (e.HostBlocklistState is EvidenceState.Observed or EvidenceState.Partial && e.HostsListed > 0) {
            signals.Add(new RiskSignal {
                Id = "reputation.host-blocklist",
                Facet = ProfileFacetKind.Reputation,
                Points = Math.Min(15, 5 * e.HostsListed),
                Reason = e.HostsListed == 1 ? "1 mail or web host address is on a blocklist" : e.HostsListed.ToString(CultureInfo.InvariantCulture) + " mail or web host addresses are on blocklists",
                Source = "DNSBL",
                CheckKey = "dnsbl"
            });
        }
    }

    private static ProfileFacet ReputationFacet(DomainRiskEvidence e) {
        var items = new List<EvidenceItem>();
        foreach (ThreatFeedEvidence feed in e.Feeds) {
            items.Add(Item("reputation." + feed.Id, feed.Name, feed.State, feed.Weight, feed.Name, "threatintel", feed.State == EvidenceState.NotQueried ? feed.Action : null));
        }
        items.Add(Item("reputation.domain-blocklist", "Domain blocklists", e.DomainBlocklistState, 0.15, "DNSBL", "dnsbl"));
        items.Add(Item("reputation.host-blocklist", "Host blocklists", e.HostBlocklistState, 0.10, "DNSBL", "dnsbl"));
        var facts = new List<ProfileFact>();
        int asked = e.Feeds.Count(static f => f.State is EvidenceState.Observed or EvidenceState.Clean);
        if (e.Feeds.Count > 0) AddFact(facts, "Threat feeds answered", asked.ToString(CultureInfo.InvariantCulture) + " of " + e.Feeds.Count.ToString(CultureInfo.InvariantCulture));
        if (e.HostsChecked > 0) {
            AddFact(facts, "Blocklisted hosts", e.HostsListed.ToString(CultureInfo.InvariantCulture) + " of " + e.HostsChecked.ToString(CultureInfo.InvariantCulture));
        }
        if (e.HighRiskLookalikes.HasValue) {
            AddFact(facts, "High-risk lookalikes", e.HighRiskLookalikes.Value.ToString(CultureInfo.InvariantCulture));
        }
        return Facet(ProfileFacetKind.Reputation, true, true, 0.30, items, facts);
    }

    // ---- Registration -----------------------------------------------------------------------------------------------

    private static string RegistrationCheck(DomainRiskEvidence e) =>
        string.Equals(e.RegistrationSource, "WHOIS", StringComparison.OrdinalIgnoreCase) ? "whois" : "rdap";

    private static void RegistrationSignals(DomainRiskEvidence e, DateTimeOffset now, List<RiskSignal> signals) {
        string source = e.RegistrationSource.Length > 0 ? e.RegistrationSource : "Registration";
        string check = RegistrationCheck(e);
        if (e.CreatedState == EvidenceState.Observed && e.CreatedUtc.HasValue) {
            double age = (now - e.CreatedUtc.Value).TotalDays;
            (string id, int points)? rule = age < 30 ? ("registration.age.under30d", 20)
                : age < 90 ? ("registration.age.under90d", 12)
                : age < 365 ? ("registration.age.under1y", 5)
                : age >= 3 * 365 ? ("registration.age.over3y", -5)
                : null;
            if (rule.HasValue) {
                string reason = rule.Value.points < 0
                    ? "Registered " + ((int)(age / 365.25)).ToString(CultureInfo.InvariantCulture) + " years ago (" + Date(e.CreatedUtc) + ")"
                    : "Registered " + Days(age) + " ago (" + Date(e.CreatedUtc) + ")";
                signals.Add(new RiskSignal { Id = rule.Value.id, Facet = ProfileFacetKind.Registration, Points = rule.Value.points, Reason = reason, Source = source, CheckKey = check });
            }
        }
        string? hold = e.Statuses.FirstOrDefault(static s => s.IndexOf("hold", StringComparison.OrdinalIgnoreCase) >= 0);
        if (hold != null && e.StatusState == EvidenceState.Observed) {
            signals.Add(new RiskSignal {
                Id = "registration.hold", Facet = ProfileFacetKind.Registration, Points = 20,
                Reason = "Registration is on hold (" + hold + ")", Source = "RDAP", CheckKey = "rdap"
            });
        }
        if (e.ExpiryState == EvidenceState.Observed && e.ExpiresUtc.HasValue && e.ExpiresUtc.Value < now) {
            signals.Add(new RiskSignal {
                Id = "registration.expired", Facet = ProfileFacetKind.Registration, Points = 15,
                Reason = "Registration expired on " + Date(e.ExpiresUtc), Source = source, CheckKey = check
            });
        }
    }

    private static ProfileFacet RegistrationFacet(DomainRiskEvidence e, DateTimeOffset now) {
        string source = e.RegistrationSource;
        string check = RegistrationCheck(e);
        var items = new List<EvidenceItem> {
            Item("registration.created", "Creation date", e.CreatedState, 0.5, source, check),
            Item("registration.expiry", "Expiry date", e.ExpiryState, 0.2, source, check),
            Item("registration.status", "Status codes", e.StatusState, 0.2, "RDAP", "rdap"),
            Item("registration.registrar", "Registrar", e.RegistrarState, 0.1, source, check)
        };
        var facts = new List<ProfileFact>();
        AddFact(facts, "Registrar", e.Registrar);
        if (e.CreatedUtc.HasValue) AddFact(facts, "Registered", Age((now - e.CreatedUtc.Value).TotalDays) + " ago (" + Date(e.CreatedUtc) + ")");
        if (e.ExpiresUtc.HasValue) AddFact(facts, "Expires", Date(e.ExpiresUtc));
        if (e.PrivacyProtected == true) AddFact(facts, "Privacy service", "Yes", "common for legitimate registrations; not scored");
        if (e.Statuses.Count > 0) AddFact(facts, "Status", string.Join(", ", e.Statuses.Take(6)));
        return Facet(ProfileFacetKind.Registration, true, true, 0.20, items, facts);
    }

    // ---- Certificates -----------------------------------------------------------------------------------------------

    private static string CtLabel(DomainRiskEvidence e) => e.CtSource switch {
        "ddct-api" => "CT (DDCT)",
        "crt.sh" => "CT (crt.sh)",
        "certspotter" => "CT (Cert Spotter)",
        "" => "CT",
        _ => "CT (" + e.CtSource + ")"
    };

    // Cert Spotter's issuance API lists recent issuances, not the whole history, so its earliest entry is not a first-seen date.
    private static bool FirstSeenIsHistory(DomainRiskEvidence e) => !e.CtCapped && e.CtSource != "certspotter";

    private static void CertificateSignals(DomainRiskEvidence e, DateTimeOffset now, List<RiskSignal> signals) {
        if (e.CtState != EvidenceState.Observed) return;
        if (e.CtFirstSeenUtc.HasValue && FirstSeenIsHistory(e)) {
            double age = (now - e.CtFirstSeenUtc.Value).TotalDays;
            if (age < 30) {
                string qualifier = e.CtSource == "ddct-api" ? "on or before " : string.Empty;
                signals.Add(new RiskSignal {
                    Id = "certificates.first-seen.under30d", Facet = ProfileFacetKind.Certificates, Points = 8,
                    Reason = "First certificate logged " + qualifier + Date(e.CtFirstSeenUtc) + " (" + Days(age) + " ago)",
                    Source = CtLabel(e), CheckKey = "cttimeline"
                });
            }
        }
        // A burst: more than five certificates this week and more than half of the month's issuance.
        if (e.IssuedLast7Days > 5 && e.IssuedLast7Days * 2 > e.IssuedLast30Days) {
            signals.Add(new RiskSignal {
                Id = "certificates.burst", Facet = ProfileFacetKind.Certificates, Points = 5,
                Reason = e.IssuedLast7Days.ToString(CultureInfo.InvariantCulture) + " certificates logged in the last 7 days (" +
                         e.IssuedLast30Days.ToString(CultureInfo.InvariantCulture) + " in 30)",
                Source = CtLabel(e), CheckKey = "cttimeline"
            });
        }
    }

    private static ProfileFacet CertificateFacet(DomainRiskEvidence e, DateTimeOffset now) {
        string source = CtLabel(e);
        bool noCertificates = e.CtState == EvidenceState.Observed && e.UniqueCertificates == 0;
        EvidenceState answered = noCertificates ? EvidenceState.Clean : e.CtState;
        EvidenceState firstSeen = e.CtState == EvidenceState.Observed && !FirstSeenIsHistory(e) ? EvidenceState.Partial : answered;
        string? firstSeenNote = e.CtState != EvidenceState.Observed ? null
            : e.CtCapped ? "CT answer was capped; the earliest entry may be missing"
            : e.CtSource == "certspotter" ? "recent issuances only; the full history was unavailable, so this is not the first certificate"
            : null;
        var items = new List<EvidenceItem> {
            Item("certificates.first-seen", "First seen", firstSeen, 0.4, source, "cttimeline", firstSeenNote),
            Item("certificates.last-seen", "Last seen", answered, 0.2, source, "cttimeline"),
            Item("certificates.issuers", "Issuers", answered, 0.2, source, "cttimeline"),
            Item("certificates.velocity", "Issuance rate", answered, 0.2, source, "cttimeline")
        };
        var facts = new List<ProfileFact>();
        if (e.CtFirstSeenUtc.HasValue) {
            AddFact(facts, FirstSeenIsHistory(e) ? "First seen" : "Earliest entry returned", Age((now - e.CtFirstSeenUtc.Value).TotalDays) + " ago (" + Date(e.CtFirstSeenUtc) + ")",
                e.CtSource == "ddct-api" ? "earliest entry DDCT has ingested" : firstSeenNote);
        }
        if (e.UniqueCertificates > 0) {
            bool partial = !FirstSeenIsHistory(e);
            AddFact(facts, partial ? "Recent certificates" : "Certificates", e.UniqueCertificates.ToString(CultureInfo.InvariantCulture) + ", " +
                                           e.IssuedLast30Days.ToString(CultureInfo.InvariantCulture) + " in the last 30 days",
                partial ? "recent issuances only; the full history was unavailable" : null);
        }
        if (e.Issuers.Count > 0) {
            string[] issuers = e.Issuers.OrderByDescending(static i => i.Value).Select(static i => IssuerName(i.Key)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            AddFact(facts, "Issuers", string.Join(", ", issuers.Take(3)) +
                                      (issuers.Length > 3 ? " and " + (issuers.Length - 3).ToString(CultureInfo.InvariantCulture) + " more" : string.Empty));
        }
        if (e.CtSource.Length > 0) AddFact(facts, "CT source", e.CtSource switch { "ddct-api" => "DDCT", "certspotter" => "Cert Spotter", _ => e.CtSource });
        return Facet(ProfileFacetKind.Certificates, true, true, 0.15, items, facts);
    }

    // ---- DNS ----------------------------------------------------------------------------------------------------------

    private static void DnsSignals(DomainRiskEvidence e, List<RiskSignal> signals) {
        if (e.DnssecState == EvidenceState.Observed && e.Dnssec == DnssecValidationStatus.Bogus) {
            signals.Add(new RiskSignal { Id = "dns.dnssec.bogus", Facet = ProfileFacetKind.Dns, Points = 10, Reason = "DNSSEC validation fails (bogus)", Source = "DNSSEC", CheckKey = "dnssec" });
        }
        if (e.DnssecState == EvidenceState.Observed && e.Dnssec == DnssecValidationStatus.Secure) {
            signals.Add(new RiskSignal { Id = "dns.dnssec.secure", Facet = ProfileFacetKind.Dns, Points = -3, Reason = "DNSSEC validates", Source = "DNSSEC", CheckKey = "dnssec" });
        }
        if (e.PtrState == EvidenceState.Observed && e.MailHostsWithoutFcrDns > 0) {
            signals.Add(new RiskSignal {
                Id = "dns.mail-ptr", Facet = ProfileFacetKind.Dns, Points = 3,
                Reason = e.MailHostsWithoutFcrDns.ToString(CultureInfo.InvariantCulture) + " mail host address(es) without forward-confirmed reverse DNS",
                Source = "Reverse DNS", CheckKey = "fcrdns"
            });
        }
    }

    private static ProfileFacet DnsFacet(DomainRiskEvidence e) {
        var items = new List<EvidenceItem> {
            Item("dns.inventory", "DNS records", e.InventoryState, 0.3, "DNS", "dnsinventory"),
            Item("dns.dnssec", "DNSSEC", e.DnssecState, 0.3, "DNSSEC", "dnssec"),
            Item("dns.ns", "Name servers", e.NameServerState, 0.2, "DNS", "ns"),
            Item("dns.ptr", "Mail host reverse DNS", e.PtrState, 0.2, "Reverse DNS", "fcrdns")
        };
        var facts = new List<ProfileFact>();
        AddFact(facts, "DNS provider", e.DnsProvider);
        AddFact(facts, "Mail provider", e.MailProvider);
        if (e.NameServers.Count > 0) AddFact(facts, "Name servers", string.Join(", ", e.NameServers.Take(4)));
        if (e.Dnssec.HasValue && e.Dnssec.Value != DnssecValidationStatus.NotChecked) AddFact(facts, "DNSSEC", e.Dnssec.Value.ToString());
        return Facet(ProfileFacetKind.Dns, true, true, 0.15, items, facts);
    }

    // ---- Network ------------------------------------------------------------------------------------------------------

    private static ProfileFacet NetworkFacet(DomainRiskEvidence e) {
        EvidenceState asn = e.NetworkState, country = e.NetworkState, hosting = e.NetworkState;
        string? countryNote = null, hostingNote = null;
        if (e.NetworkState == EvidenceState.Observed) {
            if (e.Addresses.Count == 0) {
                asn = country = hosting = EvidenceState.Clean;
            } else {
                asn = e.Addresses.Any(static a => a.Asn.HasValue || a.Cidr.Length > 0) ? EvidenceState.Observed : EvidenceState.Partial;
                if (e.Addresses.Any(static a => a.CountrySource == IpCountrySource.GeoIp)) {
                    country = EvidenceState.Observed;
                } else if (e.Addresses.Any(static a => a.CountrySource == IpCountrySource.RdapRegistration)) {
                    country = EvidenceState.Partial;
                    countryNote = "registration country (RDAP), not server location; no GeoIP data is bundled";
                } else {
                    country = EvidenceState.NotAvailable;
                    countryNote = "RDAP gave no country and no GeoIP data is bundled";
                }
                bool published = e.Addresses.Any(static a => a.HostingProvider.Length > 0 && !a.HostingMatchedBy.StartsWith("AS", StringComparison.Ordinal));
                bool network = e.Addresses.Any(static a => a.HostingProvider.Length > 0);
                if (published) {
                    hosting = EvidenceState.Observed;
                } else if (network) {
                    hosting = EvidenceState.Partial;
                    hostingNote = "matched by network only, not a published range";
                } else {
                    hosting = asn == EvidenceState.Observed ? EvidenceState.Clean : EvidenceState.Partial;
                    hostingNote = "no published cloud or CDN range matched";
                }
            }
        }
        var items = new List<EvidenceItem> {
            Item("network.asn", "Networks (ASN or CIDR)", asn, 0.5, "RDAP", "ipenrichment"),
            Item("network.country", "Country", country, 0.25, "RDAP", "ipenrichment", countryNote),
            Item("network.hosting", "Hosting and CDN", hosting, 0.25, "Published ranges", "ipenrichment", hostingNote)
        };
        var facts = new List<ProfileFact>();
        string[] hosts = e.Addresses.Where(static a => a.HostingProvider.Length > 0)
            .Select(static a => a.IsCdn ? a.HostingProvider + " (CDN)" : a.HostingProvider)
            .Distinct(StringComparer.Ordinal).ToArray();
        if (hosts.Length > 0) AddFact(facts, "Hosting", string.Join(", ", hosts));
        string[] networks = e.Addresses.Where(static a => a.Asn.HasValue)
            .GroupBy(static a => a.Asn!.Value)
            .Select(static g => "AS" + g.Key.ToString(CultureInfo.InvariantCulture) + (g.First().AsName.Length > 0 ? " " + g.First().AsName : string.Empty))
            .ToArray();
        string[] shown = networks.Length > 0 ? networks
            : e.Addresses.Select(static a => a.Cidr).Where(static c => c.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
        if (shown.Length > 0) {
            AddFact(facts, "Networks", string.Join(", ", shown.Take(3)) + (shown.Length > 3 ? " and " + (shown.Length - 3).ToString(CultureInfo.InvariantCulture) + " more" : string.Empty));
        }
        string[] countries = e.Addresses.Where(static a => a.Country.Length > 0).Select(static a => a.Country.ToUpperInvariant()).Distinct(StringComparer.Ordinal).ToArray();
        if (countries.Length > 0) {
            bool registered = e.Addresses.All(static a => a.CountrySource != IpCountrySource.GeoIp);
            AddFact(facts, registered ? "IP space registered in" : "Countries", string.Join(", ", countries));
        }
        return Facet(ProfileFacetKind.Network, true, true, 0.10, items, facts);
    }

    // ---- Web ----------------------------------------------------------------------------------------------------------

    private static ProfileFacet WebFacet(DomainRiskEvidence e) {
        bool ran = e.WebState != EvidenceState.NotQueried;
        var items = new List<EvidenceItem> {
            Item("web.technologies", "Website technologies", e.WebState, 1, "Web scan", "http")
        };
        var facts = new List<ProfileFact>();
        if (e.Technologies.Count > 0) {
            AddFact(facts, "Technologies", string.Join(", ", e.Technologies.Take(8)) +
                                           (e.Technologies.Count > 8 ? " and " + (e.Technologies.Count - 8).ToString(CultureInfo.InvariantCulture) + " more" : string.Empty));
        }
        return Facet(ProfileFacetKind.Web, false, ran, 0.10, items, facts);
    }

    private static ProfileFacet HistoryFacet() {
        var items = new List<EvidenceItem> {
            Item("history.passive-dns", "Resolution history", EvidenceState.NotAvailable, 1, "Passive DNS", null,
                "needs records kept over time; not collected by DomainDetective")
        };
        return Facet(ProfileFacetKind.History, false, false, 0.10, items, new List<ProfileFact>());
    }

    // Lowercases only a leading capital followed by a lowercase letter, so "DNS records" and "IP" keep their case.
    private static string LowerFirst(string text) =>
        text.Length > 1 && char.IsUpper(text[0]) && char.IsLower(text[1]) ? char.ToLowerInvariant(text[0]) + text.Substring(1) : text;

    private static string Capitalize(string text) => text.Length == 0 ? text : char.ToUpperInvariant(text[0]) + text.Substring(1);

    // ---- Gaps ---------------------------------------------------------------------------------------------------------

    private static List<EvidenceGap> Gaps(List<ProfileFacet> facets, double totalWeight) {
        var gaps = new List<EvidenceGap>();
        if (totalWeight <= 0) return gaps;
        ProfileFacet? reputation = facets.FirstOrDefault(static f => f.Kind == ProfileFacetKind.Reputation);
        List<EvidenceItem> feeds = reputation?.Evidence.Where(static i => i.CheckKey == "threatintel").ToList() ?? new List<EvidenceItem>();
        int answered = feeds.Count(static i => i.State is EvidenceState.Observed or EvidenceState.Clean);
        foreach (ProfileFacet facet in facets.Where(static f => f.Counted)) {
            double itemWeight = facet.Evidence.Sum(static i => i.Weight);
            if (itemWeight <= 0) continue;
            foreach (EvidenceItem item in facet.Evidence) {
                double missing = 1 - Value(item.State);
                if (missing <= 0) continue;
                double gain = Round(facet.Weight * (item.Weight / itemWeight) * missing / totalWeight);
                if (gain <= 0) continue;
                string action = Action(item);
                if (feeds.Contains(item) && item.State is EvidenceState.NotQueried or EvidenceState.Failed) {
                    action += ": threat feeds answering go from " + answered.ToString(CultureInfo.InvariantCulture) + " to " +
                              (answered + 1).ToString(CultureInfo.InvariantCulture) + " of " + feeds.Count.ToString(CultureInfo.InvariantCulture);
                }
                gaps.Add(new EvidenceGap { EvidenceId = item.Id, State = item.State, ConfidenceGain = gain, Action = action });
            }
        }
        return gaps.OrderByDescending(static g => g.ConfidenceGain).ThenBy(static g => g.EvidenceId, StringComparer.Ordinal).ToList();
    }

    private static string Action(EvidenceItem item) {
        if (item.State is EvidenceState.NotQueried or EvidenceState.NotAvailable && !string.IsNullOrWhiteSpace(item.Note)) return Capitalize(item.Note!);
        string check = item.CheckKey switch {
            "threatintel" => "threat intel",
            "dnsbl" => "DNSBL",
            "rdap" => "RDAP",
            "whois" => "WHOIS",
            "cttimeline" => "CT timeline",
            "dnsinventory" => "DNS inventory",
            "dnssec" => "DNSSEC",
            "ns" => "NS",
            "fcrdns" => "FCrDNS",
            "ipenrichment" => "IP enrichment",
            "http" => "web scan",
            _ => item.CheckKey ?? item.Label
        };
        return item.State switch {
            EvidenceState.NotQueried => "Include the " + check + " check to collect " + LowerFirst(item.Label),
            EvidenceState.Failed => "Run the " + check + " check again: the " + LowerFirst(item.Label) + " lookup failed",
            EvidenceState.Partial => string.IsNullOrWhiteSpace(item.Note)
                ? item.Label + ": some sources did not answer; run the " + check + " check again"
                : item.Label + ": " + item.Note,
            _ => item.Label + " is not available"
        };
    }
}
