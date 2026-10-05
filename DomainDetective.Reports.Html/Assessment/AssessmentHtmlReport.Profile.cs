using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

/// <summary>
/// The domain profile: one summary per area, drawn from the checks' own metrics, facts and evidence, above the list
/// of every check. Areas without a summary still list their checks, so new checks need no layout work.
/// </summary>
public static partial class AssessmentHtmlReport {
    // CAA identifiers of the issuers DD sees most, so the served certificate can be checked against the CAA record.
    private static readonly (string IssuerText, string CaaDomain)[] CaaIssuers = {
        ("Google Trust Services", "pki.goog"), ("Let's Encrypt", "letsencrypt.org"), ("Lets Encrypt", "letsencrypt.org"),
        ("DigiCert", "digicert.com"), ("Sectigo", "sectigo.com"), ("COMODO", "comodoca.com"), ("ZeroSSL", "sectigo.com"),
        ("GoDaddy", "godaddy.com"), ("Starfield", "starfieldtech.com"), ("Amazon", "amazon.com"), ("GlobalSign", "globalsign.com"),
        ("Entrust", "entrust.net"), ("SSL.com", "ssl.com"), ("Microsoft", "microsoft.com"), ("Buypass", "buypass.com")
    };

    private static void RenderDomainProfile(AssessmentReportSection section, DomainAssessment domain, CheckIds ids, DateTimeOffset generatedAt) {
        CheckAssessment? Check(string key) => domain.Checks.FirstOrDefault(c => c.Key == key);
        string? Link(CheckAssessment? check) => check == null ? null : ids.Check(domain, check);

        CheckAssessment? spf = Check("spf"), dkim = Check("dkim"), dmarc = Check("dmarc"), bimi = Check("bimi");
        CheckAssessment? mx = Check("mx"), mtasts = Check("mtasts"), tlsrpt = Check("tlsrpt"), dane = Check("dane");
        if (spf != null || dkim != null || dmarc != null) {
            section.ReportPanel(panel => {
                panel.Title("Can anyone send as " + domain.Domain + "?").TitleIcon(TablerIconType.MailShare)
                    .Subtitle("How a receiving server decides, left to right. Open a step for its check.");
                panel.AssessmentFlow(flow => {
                    flow.Label("Outbound mail authentication");
                    if (spf != null) {
                        flow.Step("SPF · who may send", Metric(spf, "Ends with") ?? OutcomeLabel(spf.Outcome), OutcomeSeverity(spf.Outcome), s => s
                            .Caption(JoinText(Suffix(Metric(spf, "DNS lookups"), "lookups"), Suffix(Metric(spf, "Authorized addresses"), "addresses"), Fact(spf, "Sending services")))
                            .Link(Link(spf)));
                    }
                    if (dkim != null) {
                        flow.Step("DKIM · signed by", Suffix(Metric(dkim, "Selectors found"), "keys") ?? OutcomeLabel(dkim.Outcome), OutcomeSeverity(dkim.Outcome), s => {
                            s.Link(Link(dkim));
                            foreach (List<string> row in TableRows(dkim, "Selectors").Take(4)) {
                                string note = Cell(row, 4);
                                s.Line(JoinText(Cell(row, 0), Cell(row, 1), note) ?? string.Empty, Has(note, "weak") ? Severity.Elevated : null);
                            }
                        });
                    }
                    if (dmarc != null) {
                        flow.Step("DMARC · policy", Metric(dmarc, "Policy") ?? Metric(dmarc, "Record") ?? OutcomeLabel(dmarc.Outcome), PolicySeverity(Metric(dmarc, "Policy"), dmarc.Outcome), s => s
                            .Caption(JoinText(Prefix("subdomains", Metric(dmarc, "Subdomains")), Prefix("applied to", Metric(dmarc, "Applied to")), Prefix("alignment", Metric(dmarc, "Alignment"))))
                            .Emphasis()
                            .Link(Link(dmarc)));
                        List<List<string>> destinations = TableRows(dmarc, "Report destinations");
                        if (destinations.Count > 0) {
                            flow.Step("Reports go to", Metric(dmarc, "Aggregate reports") ?? destinations.Count.ToString(CultureInfo.InvariantCulture), null, s => {
                                s.Link(Link(dmarc));
                                foreach (List<string> row in destinations.Take(4)) {
                                    string authorization = Cell(row, 2);
                                    s.Line(JoinText(Cell(row, 1), authorization.Length == 0 ? null : authorization.ToLowerInvariant()) ?? string.Empty,
                                        Has(authorization, "missing") || string.Equals(authorization, "No", StringComparison.OrdinalIgnoreCase) || Has(authorization, "not published") ? Severity.Elevated : null);
                                }
                            });
                        }
                    }
                    if (bimi != null) {
                        flow.Step("BIMI · brand logo", Metric(bimi, "Logo") ?? Metric(bimi, "Record") ?? OutcomeLabel(bimi.Outcome), OutcomeSeverity(bimi.Outcome), s => s
                            .Caption(Fact(bimi, "Logo problem") ?? TopFinding(bimi))
                            .Link(Link(bimi)));
                    }
                });
                if (mx != null || mtasts != null || tlsrpt != null || dane != null) {
                    panel.Add(new HtmlTag("h4").Value("How mail reaches " + domain.Domain));
                    panel.AssessmentFlow(flow => {
                        flow.Label("Inbound mail transport");
                        if (mx != null) {
                            flow.Step("MX · mail servers", Metric(mx, "Provider") ?? Suffix(Metric(mx, "Mail servers"), "servers") ?? OutcomeLabel(mx.Outcome), OutcomeSeverity(mx.Outcome), s => {
                                s.Caption(JoinText(Suffix(Metric(mx, "Mail servers"), "servers"), Prefix("IPv6", Metric(mx, "IPv6")), Prefix("backup", Metric(mx, "Backup server")))).Link(Link(mx));
                                foreach (List<string> row in TableRows(mx, "Mail servers").Take(3)) s.Line(JoinText(Cell(row, 0), Cell(row, 1)) ?? string.Empty);
                            });
                        }
                        if (mtasts != null) {
                            flow.Step("MTA-STS · TLS required", Metric(mtasts, "Mode") ?? Metric(mtasts, "Policy") ?? OutcomeLabel(mtasts.Outcome), PolicySeverity(Metric(mtasts, "Mode"), mtasts.Outcome), s => s
                                .Caption(TopFinding(mtasts))
                                .Link(Link(mtasts)));
                        }
                        if (tlsrpt != null) {
                            flow.Step("TLS-RPT · failure reports", Suffix(Metric(tlsrpt, "Report addresses"), "addresses") ?? Metric(tlsrpt, "Record") ?? OutcomeLabel(tlsrpt.Outcome), OutcomeSeverity(tlsrpt.Outcome), s => {
                                s.Link(Link(tlsrpt));
                                foreach (string item in ListItems(tlsrpt, "Report addresses").Take(2)) s.Line(item);
                            });
                        }
                        if (dane != null) {
                            string records = Fact(dane, "Number of records") ?? "0";
                            flow.Step("DANE · pinned keys", records == "0" ? "none" : records + " records", OutcomeSeverity(dane.Outcome), s => s
                                .Caption(TopFinding(dane))
                                .Link(Link(dane)));
                        }
                    });
                }
            });
        }

        CheckAssessment? dnssec = Check("dnssec"), ns = Check("ns"), caa = Check("caa"), cert = Check("cert"), http = Check("http"), ttl = Check("ttl");
        bool dns = dnssec != null || ns != null || caa != null;
        bool web = cert != null || http != null;
        if (dns || web) {
            section.ReportSplit(split => {
                split.Ratio(ReportSplitRatio.Equal);
                if (dns) split.Main(main => main.ReportPanel(panel => {
                    panel.Title("DNS foundation").TitleIcon(TablerIconType.Sitemap);
                    if (dnssec != null) {
                        string status = Fact(dnssec, "Validation status") ?? OutcomeLabel(dnssec.Outcome);
                        bool secure = string.Equals(status, "Secure", StringComparison.OrdinalIgnoreCase);
                        Severity tone = secure ? Severity.Good : OutcomeSeverity(dnssec.Outcome);
                        string tld = domain.Domain.IndexOf('.') >= 0 ? domain.Domain.Substring(domain.Domain.LastIndexOf('.') + 1) : domain.Domain;
                        panel.AssessmentFlow(flow => flow
                            .Label("DNSSEC chain of trust")
                            .Step("Root", ".", secure ? Severity.Good : null, s => s.Link(Link(dnssec)))
                            .Step("Top-level domain", tld, secure ? Severity.Good : null, s => s.Link(Link(dnssec)))
                            .Step("DNSSEC · " + status.ToLowerInvariant(), domain.Domain, tone, s => s
                                .Caption(JoinText(Prefix("DS matches", Fact(dnssec, "DS match")), Prefix("chain valid", Fact(dnssec, "Chain valid"))))
                                .Emphasis()
                                .Link(Link(dnssec))));
                    }
                    if (ns != null) {
                        panel.AssessmentChips(chips => {
                            chips.Label("Name servers");
                            foreach (string server in ListItems(ns, "NS records").Take(8)) chips.Chip(server, null, Link(ns));
                        });
                    }
                    if (caa != null) {
                        string[] allowed = ListItems(caa, "Can issue certificates for domain").ToArray();
                        string? servedIssuer = cert == null ? null : ServedIssuer(cert);
                        string? servedCaa = servedIssuer == null ? null : CaaIssuers.FirstOrDefault(i => Has(servedIssuer, i.IssuerText)).CaaDomain;
                        panel.AssessmentChips(chips => {
                            chips.Label(allowed.Length == 0 ? "Who may issue certificates (no CAA record: anyone)" : "Who may issue certificates (CAA)");
                            foreach (string issuer in allowed) {
                                bool current = servedCaa != null && string.Equals(issuer, servedCaa, StringComparison.OrdinalIgnoreCase);
                                chips.Chip(current ? issuer + " · issued the current certificate" : issuer, current ? Severity.Good : null, Link(caa));
                            }
                            if (allowed.Length > 0 && servedIssuer != null && servedCaa != null && !allowed.Contains(servedCaa, StringComparer.OrdinalIgnoreCase)) {
                                chips.Chip($"{servedIssuer} issued the current certificate but is not allowed: renewal will fail", Severity.High, Link(caa));
                            }
                        });
                    }
                    if (ttl != null && TopFinding(ttl) is { } ttlNote) {
                        panel.AssessmentChips(chips => chips.Label("Record lifetimes").Chip(ttlNote, OutcomeSeverity(ttl.Outcome), Link(ttl)));
                    }
                }));
                if (web) split.Aside(aside => aside.ReportPanel(panel => {
                    panel.Title("Web front door").TitleIcon(TablerIconType.World);
                    if (cert != null && ParseUtc(Fact(cert, "Valid from")) is { } from && ParseUtc(Fact(cert, "Valid to")) is { } to) {
                        panel.AssessmentLifetime("Certificate lifetime", from, to, generatedAt, lifetime => lifetime
                            .Caption(JoinText(ListItems(cert, "Subject alternative names").Take(3).DefaultIfEmpty(Fact(cert, "Certificate subject") ?? string.Empty).ToArray().Aggregate((a, b) => a + ", " + b),
                                ServedIssuer(cert), JoinText(Fact(cert, "Key algorithm"), Fact(cert, "Key size"))))
                            .Link(Link(cert)));
                    }
                    if (cert != null) {
                        panel.AssessmentChips(chips => {
                            chips.Label("Protocols offered");
                            ProtocolChip(chips, cert, "Supports tls10", "TLS 1.0", legacy: true, Link(cert));
                            ProtocolChip(chips, cert, "Supports tls11", "TLS 1.1", legacy: true, Link(cert));
                            ProtocolChip(chips, cert, "Supports tls12", "TLS 1.2", legacy: false, Link(cert));
                            ProtocolChip(chips, cert, "Supports tls13", "TLS 1.3", legacy: false, Link(cert));
                            ProtocolChip(chips, cert, "Http2 supported", "HTTP/2", legacy: false, Link(cert));
                            ProtocolChip(chips, cert, "Http3 supported", "HTTP/3", legacy: false, Link(cert));
                        });
                    }
                    if (http != null) {
                        string[] present = TableRows(http, "Security headers").Select(static r => Cell(r, 0)).Where(static h => h.Length > 0).ToArray();
                        var deprecated = new HashSet<string>(ListItems(http, "Missing deprecated headers"), StringComparer.OrdinalIgnoreCase);
                        string[] missing = ListItems(http, "Missing security headers").Where(h => !deprecated.Contains(h)).ToArray();
                        if (present.Length > 0 || missing.Length > 0) {
                            panel.AssessmentChips(chips => {
                                chips.Label("Security headers");
                                foreach (string header in present) {
                                    bool shortHsts = header.Equals("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase) &&
                                                     string.Equals(Fact(http, "HSTS too short"), "Yes", StringComparison.OrdinalIgnoreCase);
                                    chips.Chip(shortHsts ? header + " · too short" : header, shortHsts ? Severity.Elevated : Severity.Good, Link(http));
                                }
                                foreach (string header in missing) chips.Chip("no " + header, Severity.Low, Link(http));
                            });
                        }
                    }
                }));
            });
        }

        CheckAssessment? dnsbl = Check("dnsbl");
        if (dnsbl != null) {
            string listed = Fact(dnsbl, "Hosts listed") ?? "0";
            section.ReportPanel(panel => panel
                .Title("Reputation").TitleIcon(TablerIconType.ShieldCheck)
                .Subtitle("The domain and every address behind its mail servers, checked against blocklists.")
                .Settings(s => s.Flush())
                .AssessmentStats(stats => stats
                    .Stat(listed == "0" ? "Clean" : listed + " listed", "Blocklist result", listed == "0" ? Severity.Good : Severity.High, Link(dnsbl))
                    .Stat(Fact(dnsbl, "Providers checked") ?? "-", "Blocklists checked")
                    .Stat(Fact(dnsbl, "Hosts checked") ?? "-", "Hosts and addresses checked")));
        }
    }

    /// <summary>
    /// One sentence on what holds and what to fix first, for the top of a domain page.
    /// </summary>
    private static string DomainVerdict(DomainAssessment domain) {
        string? strengths = DomainStrengths(domain);
        string[] fixes = FixOrder(domain.Checks)
            .Take(3)
            .Select(c => c.Title + (TopFinding(c) is { } finding ? " (" + Shorten(finding.TrimEnd('.'), 48) + ")" : string.Empty))
            .ToArray();
        string first = strengths == null ? string.Empty : strengths + " ";
        string second = fixes.Length == 0 ? "Every check passed." : "Fix first: " + string.Join("; ", fixes) + ".";
        return first + second;
    }

    /// <summary>What the domain's mail and DNS controls achieve, as one sentence, or null when nothing is known.</summary>
    private static string? DomainStrengths(DomainAssessment domain) {
        var strengths = new List<string>();
        CheckAssessment? dmarc = domain.Checks.FirstOrDefault(c => c.Key == "dmarc");
        CheckAssessment? spf = domain.Checks.FirstOrDefault(c => c.Key == "spf");
        string? policy = dmarc == null ? null : Metric(dmarc, "Policy");
        if (string.Equals(policy, "reject", StringComparison.OrdinalIgnoreCase)) strengths.Add("spoofed mail is rejected (DMARC reject)");
        else if (string.Equals(policy, "quarantine", StringComparison.OrdinalIgnoreCase)) strengths.Add("spoofed mail is quarantined (DMARC quarantine)");
        else if (dmarc != null && string.Equals(Metric(dmarc, "Record"), "Unknown", StringComparison.OrdinalIgnoreCase)) strengths.Add("the DMARC policy could not be read (DNS lookup failed)");
        else if (dmarc != null) strengths.Add("DMARC does not stop spoofed mail yet");
        if (spf != null && (Metric(spf, "Ends with") ?? string.Empty).StartsWith("-all", StringComparison.Ordinal)) strengths.Add("SPF hard-fails unknown senders");
        if (domain.Checks.FirstOrDefault(c => c.Key == "dnssec") is { Outcome: CheckOutcome.Pass }) strengths.Add("DNSSEC is valid");
        return strengths.Count == 0 ? null : Capitalize(string.Join(", ", strengths)) + ".";
    }

    /// <summary>
    /// Checks that need attention, in the order to fix them: security exposure first (see
    /// <see cref="DomainAssessmentCatalog.SecurityPriority"/>), then errors before warnings, then by what costs the score
    /// most (points lost times the check's weight).
    /// </summary>
    private static IEnumerable<CheckAssessment> FixOrder(IEnumerable<CheckAssessment> checks) => checks
        .Where(static c => c.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
        .OrderBy(static c => DomainAssessmentCatalog.SecurityPriority(c.Check))
        .ThenByDescending(static c => c.Outcome)
        .ThenByDescending(static c => (100 - c.Score) * Math.Max(1, c.Weight));

    private static void ProtocolChip(AssessmentChipList chips, CheckAssessment cert, string factLabel, string text, bool legacy, string? link) {
        string? value = Fact(cert, factLabel);
        if (value == null) return;
        bool on = string.Equals(value, "Yes", StringComparison.OrdinalIgnoreCase);
        if (legacy) chips.Chip(on ? text + " on" : text + " off", on ? Severity.High : Severity.Good, link);
        else chips.Chip(on ? text : "no " + text, on ? Severity.Good : null, link);
    }

    private static string? ServedIssuer(CheckAssessment cert) {
        string? issuer = Fact(cert, "Certificate issuer");
        if (issuer == null) return null;
        // "CN=WE1, O=Google Trust Services, C=US" -> "Google Trust Services"
        string? organization = issuer.Split(',').Select(static p => p.Trim()).FirstOrDefault(static p => p.StartsWith("O=", StringComparison.OrdinalIgnoreCase))?.Substring(2);
        return string.IsNullOrWhiteSpace(organization) ? issuer : organization;
    }

    private static Severity PolicySeverity(string? policy, CheckOutcome outcome) => (policy ?? string.Empty).ToLowerInvariant() switch {
        "reject" or "enforce" => Severity.Good,
        "quarantine" or "testing" => Severity.Elevated,
        "none" => Severity.High,
        _ => OutcomeSeverity(outcome)
    };

    private static string? Metric(CheckAssessment check, string label)
        => check.Metrics.FirstOrDefault(m => string.Equals(m.Label, label, StringComparison.OrdinalIgnoreCase))?.Value is { Length: > 0 } value ? value : null;

    private static string? Fact(CheckAssessment check, string label)
        => check.Facts.FirstOrDefault(f => string.Equals(f.Label, label, StringComparison.OrdinalIgnoreCase))?.Value is { Length: > 0 } value ? value : null;

    private static IEnumerable<string> ListItems(CheckAssessment check, string title)
        => check.Evidence.FirstOrDefault(e => string.Equals(e.Title, title, StringComparison.OrdinalIgnoreCase))?.Items ?? Enumerable.Empty<string>();

    private static List<List<string>> TableRows(CheckAssessment check, string title)
        => check.Evidence.FirstOrDefault(e => string.Equals(e.Title, title, StringComparison.OrdinalIgnoreCase))?.Rows ?? new List<List<string>>();

    private static string Cell(List<string> row, int index) => index < row.Count ? row[index] ?? string.Empty : string.Empty;

    private static string? TopFinding(CheckAssessment check)
        => check.Findings.FirstOrDefault(static f => f.Severity != AssessmentSeverity.Info)?.Message;

    private static string? JoinText(params string?[] parts) {
        string joined = string.Join(" · ", parts.Where(static p => !string.IsNullOrWhiteSpace(p)));
        return joined.Length == 0 ? null : joined;
    }

    private static string? Suffix(string? value, string suffix) {
        if (string.IsNullOrWhiteSpace(value)) return null;
        // "1 keys" reads wrong: a count of one takes the singular.
        if (value!.Trim() == "1") {
            if (suffix.EndsWith("sses", StringComparison.Ordinal)) suffix = suffix.Substring(0, suffix.Length - 2);
            else if (suffix.EndsWith("s", StringComparison.Ordinal)) suffix = suffix.Substring(0, suffix.Length - 1);
        }
        return value + " " + suffix;
    }

    private static string? Prefix(string prefix, string? value) => string.IsNullOrWhiteSpace(value) ? null : prefix + " " + value;

    private static string Shorten(string text, int max) => text.Length <= max ? text : text.Substring(0, max - 1).TrimEnd() + "…";

    private static bool Has(string? text, string value) => text != null && text.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;

    private static string Capitalize(string text) => text.Length == 0 ? text : char.ToUpperInvariant(text[0]) + text.Substring(1);

    private static DateTimeOffset? ParseUtc(string? text) {
        if (string.IsNullOrWhiteSpace(text)) return null;
        string[] formats = { "yyyy-MM-dd HH:mm 'UTC'", "yyyy-MM-dd HH:mm:ss 'UTC'", "yyyy-MM-dd" };
        return DateTimeOffset.TryParseExact(text!.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset value)
            ? value
            : null;
    }
}
