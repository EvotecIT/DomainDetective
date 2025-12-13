using System;
using OfficeIMO.Word;
using System.Linq;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Writes a Mail Classification section (Sending/Receiving/Parked) into Word documents.
/// </summary>
public static class MailClassificationWordSectionWriter
{
    /// <summary>
    /// Writes Mail Classification section.
    /// </summary>
    /// <param name="doc">Target document.</param>
    /// <param name="info">Mail classification view.</param>
    /// <param name="domain">Subject domain.</param>
    /// <param name="scope">Detail level.</param>
    /// <param name="showInfoFindings">Include Info-level findings.</param>
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.MailClassificationInfo info, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (info == null) throw new ArgumentNullException(nameof(info));

        // Intro paragraph
        var intro = $"Based on discovered signals, this domain is classified as {info.Classification} with {info.Confidence} confidence.";
        doc.AddParagraph(intro);
        // Signals considered (always render both lines with fallback when one is empty)
        {
            var sig = doc.AddParagraph("Signals considered:");
            var list = doc.AddList(WordListStyle.Bulleted);
            var recv = (info.ReceivingSignals != null && info.ReceivingSignals.Count > 0)
                ? string.Join(", ", info.ReceivingSignals)
                : "None";
            var send = (info.SendingSignals != null && info.SendingSignals.Count > 0)
                ? string.Join(", ", info.SendingSignals)
                : "None";
            list.AddItem($"Receiving: {recv}");
            list.AddItem($"Sending: {send}");
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Mail classification outcome and scoring.");
        var t = doc.AddTable(8, 2, WordTableStyle.TableGrid);
        t.Rows[0].Cells[0].AddParagraph("Classification");
        t.Rows[0].Cells[1].AddParagraph(info.Classification ?? string.Empty);
        t.Rows[1].Cells[0].AddParagraph("Confidence");
        t.Rows[1].Cells[1].AddParagraph(info.Confidence ?? string.Empty);
        t.Rows[2].Cells[0].AddParagraph("Score");
        t.Rows[2].Cells[1].AddParagraph(info.Score.ToString("0.##"));
        t.Rows[3].Cells[0].AddParagraph("Inline Summary");
        t.Rows[3].Cells[1].AddParagraph(info.Summary ?? string.Empty);
        t.Rows[4].Cells[0].AddParagraph("Status");
        t.Rows[4].Cells[1].AddParagraph(info.Status ?? string.Empty);
        t.Rows[5].Cells[0].AddParagraph("Primary Provider");
        t.Rows[5].Cells[1].AddParagraph(info.ProviderPrimary ?? string.Empty);
        t.Rows[6].Cells[0].AddParagraph("Gateways");
        t.Rows[6].Cells[1].AddParagraph(info.ProviderGateways != null && info.ProviderGateways.Count > 0 ? string.Join(", ", info.ProviderGateways) : string.Empty);
        t.Rows[7].Cells[0].AddParagraph("Outbound Senders");
        t.Rows[7].Cells[1].AddParagraph(info.ProviderOutbound != null && info.ProviderOutbound.Count > 0 ? string.Join(", ", info.ProviderOutbound) : string.Empty);

        // Score Breakdown + Scoring rubric
        if (info.ScoreBreakdown != null && info.ScoreBreakdown.Count > 0)
        {
            headings.AddItem("Score Breakdown", baseLevel);
            doc.AddParagraph("How the score was calculated.");
            var sb = info.ScoreBreakdown.ToList();
            var sbt = doc.AddTable(sb.Count + 1, 2, WordTableStyle.TableGrid);
            sbt.Rows[0].Cells[0].AddParagraph("Signal");
            sbt.Rows[0].Cells[1].AddParagraph("Points");
            for (int i = 0; i < sb.Count; i++)
            {
                sbt.Rows[i + 1].Cells[0].AddParagraph(sb[i].Key);
                sbt.Rows[i + 1].Cells[1].AddParagraph(sb[i].Value.ToString("0.##"));
            }
        }
        // Scoring rubric note (always present)
        {
            var rubric = doc.AddParagraph("Scoring rubric: signals add/subtract points; classification thresholds are documented.");
            var link = doc.AddParagraph("See documentation: Docs/REPORTS.MD (Mail Classification)");
            link.FontSize = 10;
        }

        // Good posture
        if (scope != ReportScope.Minimal && info.Positives != null && info.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("This domain demonstrates the following positive posture:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in info.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = info.Assessments?.ToList() ?? new System.Collections.Generic.List<DomainDetective.Assessment>();
        if (!showInfoFindings) assessments = assessments.Where(a => a.Severity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (assessments.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            doc.AddParagraph("The following issues were detected:");
            var ft = doc.AddTable(assessments.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < assessments.Count; i++)
            {
                var a = assessments[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity.ToString());
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code ?? string.Empty);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target ?? string.Empty);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }
        else
        {
            doc.AddParagraph("No findings.");
        }

        // Recommendations (Detailed only when there are problems)
        var groups = DomainDetective.RecommendationEngine.GroupByCode(assessments);
        var negative = groups.Where(g => g.MaxSeverity != DomainDetective.AssessmentSeverity.Info).ToList();
        if (negative.Count > 0)
        {
            headings.AddItem("Recommendations", baseLevel);
            var rt = doc.AddTable(negative.Count + 1, 3, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("Code");
            rt.Rows[0].Cells[1].AddParagraph("Title");
            rt.Rows[0].Cells[2].AddParagraph("How");
            for (int i = 0; i < negative.Count; i++)
            {
                var rv = negative[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(rv.Code ?? string.Empty);
                rt.Rows[i + 1].Cells[1].AddParagraph(rv.Advice?.Title ?? string.Empty);
                rt.Rows[i + 1].Cells[2].AddParagraph(rv.Advice?.How ?? string.Empty);
            }
        }

        // References
        if (info.References != null && info.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, info.References);
        }
    }
}
