using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Profiles;
using DomainDetective.Reports;
using static DomainDetective.Reports.AssessmentReportWording;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

/// <summary>
/// The risk profile panel: a verdict in a word with its reason, how much evidence was seen, the configuration grade,
/// what moved the score, what to watch, the facts grouped by subject, and what would let the report see more.
/// </summary>
public static partial class AssessmentHtmlReport {
    private static void RenderRiskProfile(AssessmentReportSection section, DomainAssessment domain, CheckIds ids) {
        DomainRiskProfile? profile = domain.RiskProfile;
        if (profile == null) return;
        string? Href(string? key) {
            CheckAssessment? check = key == null ? null : domain.Checks.FirstOrDefault(c => c.Key == key);
            return check == null ? null : "#" + ids.Check(domain, check);
        }

        section.ReportPanel(panel => {
            panel.Title(RiskTitle(domain.Domain)).TitleIcon(TablerIconType.ShieldHalf);
            var body = new HtmlTag("div").Class("dd-risk").Attribute("data-dd-risk-profile", domain.Domain);

            // Verdict, evidence seen, configuration.
            // How much was seen is the evidence score; the single-source cap and corroboration change confidence, not coverage.
            int seen = (int)Math.Round(profile.EvidenceScore * 100, MidpointRounding.AwayFromZero);
            var head = new HtmlTag("div").Class("dd-risk-head")
                .Value(new HtmlTag("div").Class(RiskToneClass(profile))
                    .Value(new HtmlTag("div").Class("dd-risk-word").Value(RiskWord(profile)))
                    .Value(RiskReasonTag(profile, Href("typosquatting"))))
                .Value(new HtmlTag("div").Class("dd-kpi " + (profile.Confidence == EvidenceConfidence.Low ? "dd-tone-neutral" : "dd-tone-info"))
                    .Value(Span("Evidence seen", "dd-kpi-label"))
                    .Value(Span(seen.ToString(CultureInfo.InvariantCulture) + "%", "dd-kpi-value"))
                    .Value(new HtmlTag("div").Class("dd-bar").Attribute("aria-hidden", "true")
                        .Value(new HtmlTag("i").Style("width", seen.ToString(CultureInfo.InvariantCulture) + "%").Style("background", "var(--dd-tone)")))
                    .Value(Span(ConfidenceLabel(profile.Confidence) + " confidence" + (profile.RestsOn != null ? ", rests on " + profile.RestsOn : string.Empty), "dd-kpi-note")));
            if (domain.Score.HasValue) {
                head.Value(new HtmlTag("div").Class("dd-kpi")
                    .Value(Span("Configuration", "dd-kpi-label"))
                    .Value(Span(domain.Grade + " · " + domain.Score.Value.ToString(CultureInfo.InvariantCulture), "dd-kpi-value"))
                    .Value(Span(domain.Coverage is < 0.995 ? CoveragePercent(domain.Coverage) + " of scored check weight judged" : "every scored check judged", "dd-kpi-note")));
            }
            body.Value(head);

            // What moved the score.
            List<RiskSignal> risks = profile.Signals.Where(static s => s.Points > 0).ToList();
            if (risks.Count > 0) {
                var list = new HtmlTag("ul").Class("dd-signals");
                foreach (RiskSignal signal in risks) {
                    list.Value(new HtmlTag("li").Class(signal.Decisive || signal.Points >= 20 ? "dd-tone-bad" : "dd-tone-warn")
                        .Value(Span(Points(signal.Points), "dd-pts"))
                        .Value(Href(signal.CheckKey) is { } link
                            ? new HtmlTag("a").Attribute("href", link).Style("color", "inherit").Value(signal.Reason)
                            : Span(signal.Reason))
                        .Value(Span(signal.Decisive ? signal.Source + ", holds the level at High" : signal.Source, "dd-src")));
                }
                body.Value(list);
            }
            // With risk signals the reason line names the strongest one, so watch items get their own line.
            if (risks.Count > 0) {
                foreach (string watch in profile.Watch) {
                    var note = new HtmlTag("p").Class("dd-note dd-watch").Value(new HtmlTag("b").Value("Watch: ")).Value(Capitalize(watch) + ". ");
                    if (Href("typosquatting") is { } lookalikes) note.Value(new HtmlTag("a").Attribute("href", lookalikes).Style("color", "var(--hfx-color-accent-text)").Value("Open lookalikes"));
                    body.Value(note);
                }
            }
            List<RiskSignal> trust = TrustSignals(profile).ToList();
            if (trust.Count > 0) {
                body.Value(new HtmlTag("p").Class("dd-note").Value(new HtmlTag("b").Value("In its favour: "))
                    .Value(string.Join("; ", trust.Select(static s => LowerFirstWord(s.Reason))) + "."));
            }

            // Where the evidence came from.
            var cover = new HtmlTag("div").Class("dd-cover").Attribute("aria-label", "Evidence by area");
            foreach (ProfileFacet facet in profile.Facets) {
                string state = FacetState(facet);
                string css = state == "seen" ? "dd-seen" : state == "partly seen" ? "dd-part" : "dd-none";
                cover.Value(new HtmlTag("span").Class(css).Attribute("title", FacetEvidence(facet)).Value(FacetLabel(facet.Kind) + ": " + state));
            }
            body.Value(cover);

            // Facts, grouped so the eye can scan them.
            var groups = profile.Facets.SelectMany(static f => f.Facts.Select(fact => (Block: FactBlock(f.Kind), Fact: fact)))
                .GroupBy(static x => x.Block).ToDictionary(static g => g.Key, static g => g.Select(static x => x.Fact).ToList());
            if (groups.Count > 0) {
                var facts = new HtmlTag("div").Class("dd-facts");
                foreach (string block in FactBlocks) {
                    if (!groups.TryGetValue(block, out List<ProfileFact>? items)) continue;
                    var dl = new HtmlTag("dl");
                    foreach (ProfileFact fact in items) {
                        dl.Value(new HtmlTag("dt").Value(fact.Label));
                        dl.Value(new HtmlTag("dd").Value(string.IsNullOrWhiteSpace(fact.Note) ? fact.Value : fact.Value + " (" + fact.Note + ")"));
                    }
                    facts.Value(new HtmlTag("div").Value(new HtmlTag("h4").Value(block)).Value(dl));
                }
                body.Value(facts);
            }

            // What would let the report see more.
            List<EvidenceGap> gaps = TopGaps(profile).ToList();
            if (gaps.Count > 0) {
                var ul = new HtmlTag("ul");
                foreach (EvidenceGap gap in gaps) ul.Value(new HtmlTag("li").Value(GapLine(gap)));
                body.Value(new HtmlTag("div").Class("dd-gaps").Value(new HtmlTag("h4").Value("To see more")).Value(ul));
            }
            panel.Add(body);
        });
    }

    private static HtmlTag RiskReasonTag(DomainRiskProfile profile, string? lookalikes) {
        var reason = new HtmlTag("p").Class("dd-risk-reason").Value(RiskReason(profile));
        if (lookalikes != null && profile.Watch.Count > 0 && !profile.Signals.Any(static s => s.Points > 0)) {
            reason.Value(" ").Value(new HtmlTag("a").Attribute("href", lookalikes).Style("color", "var(--hfx-color-accent-text)").Value("Open lookalikes"));
        }
        return reason;
    }

    private static string LowerFirstWord(string text) =>
        text.Length > 1 && char.IsUpper(text[0]) && char.IsLower(text[1]) ? char.ToLowerInvariant(text[0]) + text.Substring(1) : text;

    private static string RiskToneClass(DomainRiskProfile profile) {
        if (!profile.Rated) return "dd-tone-neutral";
        return profile.RiskLevel switch {
            DomainRiskLevel.Critical or DomainRiskLevel.High => "dd-tone-bad",
            DomainRiskLevel.Medium => "dd-tone-warn",
            DomainRiskLevel.Low => "dd-tone-warn",
            _ => profile.Watch.Count > 0 ? "dd-tone-warn" : profile.Confidence == EvidenceConfidence.High ? "dd-tone-good" : "dd-tone-neutral"
        };
    }

    /// <summary>Several domains: one card per domain with a risk profile, riskiest first.</summary>
    private static void RenderRiskByDomain(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        List<DomainAssessment> profiled = RiskOrder(report).ToList();
        if (profiled.Count == 0) return;
        section.ReportPanel(panel => panel
            .Title("Risk by domain")
            .Subtitle("Riskiest first. Risk comes from registration, reputation, certificates, DNS and hosting; configuration is graded separately.")
            .Settings(s => s.Flush())
            .AssessmentScopes(list => {
                list.Settings(s => s.Layout(AssessmentScopeLayout.Cards));
                foreach (DomainAssessment domain in profiled) {
                    DomainRiskProfile profile = domain.RiskProfile!;
                    list.Scope(domain.Domain, RiskSeverity(profile), item => {
                        item.Status(RiskWord(profile));
                        item.Metric("Risk", profile.Rated ? profile.RiskScore.ToString(CultureInfo.InvariantCulture) : "Not rated", RiskSeverity(profile));
                        item.Metric("Evidence seen", ((int)Math.Round(profile.EvidenceScore * 100)).ToString(CultureInfo.InvariantCulture) + "%");
                        item.Metric("Configuration", domain.Score.HasValue ? domain.Grade : "Not judged", GradeSeverity(domain.Score));
                        item.Note(RiskReason(profile));
                        item.Link("Open domain", ids.Domain(domain));
                    });
                }
            }));
    }

    private static Severity RiskSeverity(DomainRiskProfile profile) => !profile.Rated ? Severity.Skipped : profile.RiskLevel switch {
        DomainRiskLevel.Critical => Severity.Severe,
        DomainRiskLevel.High => Severity.High,
        DomainRiskLevel.Medium => Severity.Elevated,
        DomainRiskLevel.Low => Severity.Low,
        _ => profile.Watch.Count > 0 ? Severity.Elevated : profile.Confidence == EvidenceConfidence.High ? Severity.Good : Severity.Skipped
    };
}
