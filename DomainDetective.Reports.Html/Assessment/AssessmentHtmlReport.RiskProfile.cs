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
/// The risk profile panel: how risky the domain looks, how sure that is, why, and what would raise confidence. It opens
/// the domain profile, ahead of the configuration panels.
/// </summary>
public static partial class AssessmentHtmlReport {
    private static void RenderRiskProfile(AssessmentReportSection section, DomainAssessment domain, CheckIds ids) {
        DomainRiskProfile? profile = domain.RiskProfile;
        if (profile == null) return;
        string? Link(string? key) {
            CheckAssessment? check = key == null ? null : domain.Checks.FirstOrDefault(c => c.Key == key);
            return check == null ? null : ids.Check(domain, check);
        }

        section.ReportPanel(panel => {
            panel.Title(RiskTitle(domain.Domain)).TitleIcon(TablerIconType.ShieldHalf).Subtitle(RiskSubtitle);
            panel.Add(new HtmlTag("span").Attribute("data-dd-risk-profile", domain.Domain).Attribute("hidden", "hidden"));
            panel.AssessmentStats(stats => stats
                .Stat(RiskValue(profile), "Risk · 0–100", RiskSeverity(profile))
                .Stat(ConfidenceValue(profile), "Confidence · how much evidence was seen", ConfidenceSeverity(profile))
                .Stat(domain.Score.HasValue ? domain.Grade + " · " + domain.Score.Value.ToString(CultureInfo.InvariantCulture) : "Not scored",
                    "Posture · configuration grade", GradeSeverity(domain.Score)));
            panel.Text(RiskVerdict(profile) + (ConfidenceNote(profile) is { } note ? " " + note : string.Empty));

            List<RiskSignal> signals = ShownSignals(profile).ToList();
            if (signals.Count > 0) {
                panel.AssessmentAssertions(assertions => {
                    assertions.Settings(s => s.Labels("Why", "No risk signals", "{0} trust signals", observed: "Source"));
                    foreach (RiskSignal signal in signals) {
                        bool trust = signal.Points < 0;
                        assertions.Assertion(signal.Reason, trust ? Severity.Good : SignalSeverity(signal), trust, a => a
                            .Observed(SignalSource(signal))
                            .SeverityLabel(Points(signal.Points)));
                    }
                });
            }

            panel.AssessmentChips(chips => {
                chips.Label("Evidence by area");
                foreach (ProfileFacet facet in profile.Facets) {
                    string text = FacetLabel(facet.Kind) + " · " + FacetCoverage(facet);
                    Severity? tone = !facet.Counted || facet.Coverage < 0.5 ? Severity.Skipped : null;
                    chips.Chip(text, tone, Link(facet.Evidence.FirstOrDefault(static e => e.CheckKey != null)?.CheckKey));
                }
            });

            List<ProfileFact> facts = profile.Facets.SelectMany(static f => f.Facts).ToList();
            if (facts.Count > 0) {
                panel.Add(new HtmlTag("h4").Value("What is known"));
                panel.AssessmentFacts(list => {
                    foreach (ProfileFact fact in facts) {
                        string value = string.IsNullOrWhiteSpace(fact.Note) ? fact.Value : fact.Value + " · " + fact.Note;
                        list.Fact(fact.Label, value, value.Length > 40);
                    }
                });
            }

            List<EvidenceGap> gaps = TopGaps(profile).ToList();
            if (gaps.Count > 0) {
                panel.Add(new HtmlTag("h4").Value("What would raise confidence"));
                var listTag = new HtmlTag("ol");
                foreach (EvidenceGap gap in gaps) listTag.Value(new HtmlTag("li").Value(GapLine(gap)));
                panel.Add(listTag);
            }
        });
    }

    /// <summary>Several domains: one card per domain with a risk profile, riskiest first.</summary>
    private static void RenderRiskByDomain(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        List<DomainAssessment> profiled = RiskOrder(report).ToList();
        if (profiled.Count == 0) return;
        section.ReportPanel(panel => panel
            .Title("Risk by domain")
            .Subtitle("Riskiest first. Risk and confidence come from registration, reputation, CT, DNS and network evidence; posture is the configuration grade.")
            .Settings(s => s.Flush())
            .AssessmentScopes(list => {
                list.Settings(s => s.Layout(AssessmentScopeLayout.Cards));
                foreach (DomainAssessment domain in profiled) {
                    DomainRiskProfile profile = domain.RiskProfile!;
                    list.Scope(domain.Domain, RiskSeverity(profile), item => {
                        item.Status(profile.Rated ? RiskLevelLabel(profile.RiskLevel) + " risk" : "Not rated");
                        item.Metric("Risk", profile.Rated ? profile.RiskScore.ToString(CultureInfo.InvariantCulture) : "Not rated", RiskSeverity(profile));
                        item.Metric("Confidence", ConfidenceValue(profile), ConfidenceSeverity(profile));
                        item.Metric("Posture", domain.Score.HasValue ? domain.Grade : "Not scored", GradeSeverity(domain.Score));
                        item.Note(ShownSignals(profile).FirstOrDefault()?.Reason ?? RiskVerdict(profile));
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
        _ => profile.Confidence == EvidenceConfidence.High ? Severity.Good : Severity.Informational
    };

    private static Severity ConfidenceSeverity(DomainRiskProfile profile) =>
        profile.Confidence == EvidenceConfidence.Low ? Severity.Skipped : Severity.Informational;

    private static Severity SignalSeverity(RiskSignal signal) => signal.Decisive || signal.Points >= 20 ? Severity.High
        : signal.Points >= 8 ? Severity.Elevated
        : Severity.Low;
}
