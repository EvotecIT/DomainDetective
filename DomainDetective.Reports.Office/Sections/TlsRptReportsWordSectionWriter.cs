using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class TlsRptReportsWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Views.TlsRptReportsTimeSeriesInfo reports,
        string domain,
        ReportScope scope,
        bool showInfoFindings,
        bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (reports == null) throw new ArgumentNullException(nameof(reports));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.TlsRptReportsNarrative.Build(domain);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("TLS-RPT delivery outcomes based on ingested SMTP TLS reports.");

        int ok = reports.TotalSuccessfulSessions;
        int fail = reports.TotalFailedSessions;
        int total = ok + fail;

        var rows = new List<(string Key, string Value)>
        {
            ("Period Start (UTC)", reports.PeriodStartUtc?.UtcDateTime.ToString("u") ?? "-"),
            ("Period End (UTC)", reports.PeriodEndUtc?.UtcDateTime.ToString("u") ?? "-"),
            ("Reports", reports.SnapshotCount.ToString()),
            ("Successful Sessions", ok.ToString()),
            ("Failed Sessions", fail.ToString()),
            ("Failure Rate %", total > 0 ? reports.FailureRatePercent.ToString("0.0") : "-"),
            ("Status", reports.Status ?? "-")
        };

        if (reports.TopFailureTypes != null && reports.TopFailureTypes.Count > 0)
        {
            var top = reports.TopFailureTypes
                .Take(5)
                .Select(kv => $"{kv.Key}={kv.Count}");
            rows.Add(("Top failures (types)", string.Join(", ", top)));
        }

        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Key);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Value);
        }

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (reports.Positives != null && reports.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("Positive posture signals observed in the ingested TLS-RPT reports:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in reports.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (reports.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
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
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message ?? string.Empty);
            }
        }

        if (scope == ReportScope.Detailed)
        {
            if (reports.Daily != null && reports.Daily.Count > 0)
            {
                headings.AddItem("Trends", baseLevel);
                doc.AddParagraph("Daily rollups over the reporting period (capped).");
                const int maxRows = 31;
                var daily = reports.Daily.OrderBy(x => x.DateUtc).ToList();
                if (daily.Count > maxRows)
                {
                    daily = daily.Skip(daily.Count - maxRows).ToList();
                }

                var dt = doc.AddTable(daily.Count + 1, 4, WordTableStyle.TableGrid);
                dt.Rows[0].Cells[0].AddParagraph("Date (UTC)");
                dt.Rows[0].Cells[1].AddParagraph("OK");
                dt.Rows[0].Cells[2].AddParagraph("Fail");
                dt.Rows[0].Cells[3].AddParagraph("Fail %");
                for (int i = 0; i < daily.Count; i++)
                {
                    var d = daily[i];
                    dt.Rows[i + 1].Cells[0].AddParagraph(d.DateUtc.ToString("yyyy-MM-dd"));
                    dt.Rows[i + 1].Cells[1].AddParagraph(d.SuccessfulSessions.ToString());
                    dt.Rows[i + 1].Cells[2].AddParagraph(d.FailedSessions.ToString());
                    dt.Rows[i + 1].Cells[3].AddParagraph(d.FailureRatePercent.ToString("0.0"));
                }
            }

            if (reports.MxHosts != null && reports.MxHosts.Count > 0)
            {
                headings.AddItem("Top affected MX hosts", baseLevel);
                var mxRows = reports.MxHosts
                    .OrderByDescending(x => x.FailedSessions)
                    .ThenBy(x => x.MxHost, StringComparer.OrdinalIgnoreCase)
                    .Take(20)
                    .ToList();
                var mt = doc.AddTable(mxRows.Count + 1, 4, WordTableStyle.TableGrid);
                mt.Rows[0].Cells[0].AddParagraph("MX Host");
                mt.Rows[0].Cells[1].AddParagraph("OK");
                mt.Rows[0].Cells[2].AddParagraph("Fail");
                mt.Rows[0].Cells[3].AddParagraph("Top failure types");
                for (int i = 0; i < mxRows.Count; i++)
                {
                    var r = mxRows[i];
                    var topTypes = (r.FailureByType ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
                        .OrderByDescending(kv => kv.Value)
                        .Take(3)
                        .Select(kv => $"{kv.Key}={kv.Value}");
                    mt.Rows[i + 1].Cells[0].AddParagraph(r.MxHost ?? string.Empty);
                    mt.Rows[i + 1].Cells[1].AddParagraph(r.SuccessfulSessions.ToString());
                    mt.Rows[i + 1].Cells[2].AddParagraph(r.FailedSessions.ToString());
                    mt.Rows[i + 1].Cells[3].AddParagraph(string.Join(", ", topTypes));
                }
            }
        }

        // References
        if (reports.References != null && reports.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, reports.References);
        }
    }
}

