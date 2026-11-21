using System.Collections.Generic;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Markdown;

public static partial class AssessmentMarkdownReport {
    /// <summary>The risk profile under a domain heading, before its checks.</summary>
    private static void WriteRiskProfile(MarkdownDocument document, DomainAssessment domain) {
        DomainRiskProfile? profile = domain.RiskProfile;
        if (profile == null) { return; }
        document.H3("Risk profile");
        var lead = new InlineSequence().Bold(InlineText(Wording.RiskVerdict(profile)));
        string tail = string.Join(" ", new[] {
            Wording.ConfidenceNote(profile),
            "Posture grade " + (domain.Score.HasValue ? domain.Grade : "not scored") + "."
        }.Where(static s => !string.IsNullOrWhiteSpace(s)));
        lead.Text(" " + InlineText(tail));
        document.Add(new ParagraphBlock(lead));

        List<RiskSignal> signals = Wording.ShownSignals(profile).ToList();
        if (signals.Count > 0) {
            AddTable(document, new[] { "Points", "Why", "Source" },
                signals.Select(static s => new[] { Wording.Points(s.Points), s.Reason, Wording.SignalSource(s) }));
        }
        AddTable(document, new[] { "Area", "Coverage", "Missing or partial evidence" },
            profile.Facets.Select(static f => new[] { Wording.FacetLabel(f.Kind), Wording.FacetCoverage(f), Wording.FacetEvidence(f) }));
        List<ProfileFact> facts = profile.Facets.SelectMany(static f => f.Facts).ToList();
        if (facts.Count > 0) {
            AddTable(document, new[] { "Known", "Value" },
                facts.Select(static f => new[] { f.Label, string.IsNullOrWhiteSpace(f.Note) ? f.Value : f.Value + " (" + f.Note + ")" }));
        }
        List<EvidenceGap> gaps = Wording.TopGaps(profile).ToList();
        if (gaps.Count > 0) {
            document.P(InlineText("What would raise confidence: " + string.Join("; ", gaps.Select(Wording.GapLine)) + "."));
        }
    }

    /// <summary>Several domains: risk and confidence per domain, riskiest first.</summary>
    private static void WriteRiskSummary(MarkdownDocument document, DomainAssessmentReport report) {
        List<DomainAssessment> profiled = Wording.RiskOrder(report).ToList();
        if (profiled.Count < 2) { return; }
        document.H2("Risk by domain");
        AddTable(document, new[] { "Domain", "Risk", "Confidence", "Posture", "Top signal" },
            profiled.Select(static d => new[] {
                d.Domain, Wording.RiskValue(d.RiskProfile!), Wording.ConfidenceValue(d.RiskProfile!), d.Score.HasValue ? d.Grade : "Not scored",
                Wording.ShownSignals(d.RiskProfile!).FirstOrDefault()?.Reason ?? Wording.RiskVerdict(d.RiskProfile!)
            }));
    }
}
