using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

public static class RegistrationWordSectionWriter
{
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Views.RegistrationDriftInfo registration,
        string domain,
        ReportScope scope,
        bool showInfoFindings,
        bool includeNarrative = true)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (registration == null) throw new ArgumentNullException(nameof(registration));

        if (includeNarrative)
        {
            var nar = DomainDetective.Narratives.RegistrationNarrative.Build(domain);
            if (!string.IsNullOrWhiteSpace(nar.Introduction)) { headings.AddItem("Introduction", baseLevel); doc.AddParagraph(nar.Introduction); }
            if (!string.IsNullOrWhiteSpace(nar.WhyItMatters)) { headings.AddItem("Why this matters", baseLevel); doc.AddParagraph(nar.WhyItMatters); }
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Unified WHOIS/RDAP registration snapshot and structured drift between snapshots.");

        var current = registration.Current;
        var previous = registration.Previous;
        var changes = registration.Drift?.Changes?.Count ?? 0;

        var rows = new List<(string Key, string Value)>
        {
            ("Captured (UTC)", current != null ? current.CapturedAtUtc.UtcDateTime.ToString("u") : "-"),
            ("Previous (UTC)", previous != null ? previous.CapturedAtUtc.UtcDateTime.ToString("u") : "-"),
            ("Snapshots", registration.SnapshotCount.ToString(CultureInfo.InvariantCulture)),
            ("Changes", changes.ToString(CultureInfo.InvariantCulture)),
            ("Registrar", current?.Registrar ?? "-"),
            ("Registrar ID", current?.RegistrarId ?? "-"),
            ("Created (UTC)", current?.CreatedAtUtc?.UtcDateTime.ToString("u") ?? current?.CreatedAtRaw ?? "-"),
            ("Updated (UTC)", current?.UpdatedAtUtc?.UtcDateTime.ToString("u") ?? current?.UpdatedAtRaw ?? "-"),
            ("Expires (UTC)", current?.ExpiresAtUtc?.UtcDateTime.ToString("u") ?? current?.ExpiresAtRaw ?? "-"),
            ("RDAP available", current != null ? (current.HasRdap ? "Yes" : "No") : "-"),
            ("WHOIS available", current != null ? (current.HasWhois ? "Yes" : "No") : "-"),
            ("WHOIS server", current?.WhoisServerUsed ?? "-"),
            ("WHOIS lookup source", current?.WhoisLookupSource ?? "-"),
            ("Status", registration.Status ?? "-")
        };

        if (current?.RegistrarLocked.HasValue == true)
        {
            rows.Add(("Registrar lock", current.RegistrarLocked.Value ? "Yes" : "No"));
        }
        if (current?.PrivacyProtected.HasValue == true)
        {
            rows.Add(("Privacy protected", current.PrivacyProtected.Value ? "Yes" : "No"));
        }
        if (current?.NameServers != null && current.NameServers.Count > 0)
        {
            rows.Add(("Name servers", current.NameServers.Count.ToString(CultureInfo.InvariantCulture)));
        }
        if (current?.Status != null && current.Status.Count > 0)
        {
            rows.Add(("RDAP statuses", current.Status.Count.ToString(CultureInfo.InvariantCulture)));
        }

        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Key);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Value);
        }

        if (scope == ReportScope.Minimal) return;

        // Good posture
        if (registration.Positives != null && registration.Positives.Count > 0)
        {
            headings.AddItem("Good posture", baseLevel);
            doc.AddParagraph("Positive posture signals observed in the registration snapshot:");
            var plist = doc.AddList(WordListStyle.Bulleted);
            foreach (var p in registration.Positives)
            {
                if (!string.IsNullOrWhiteSpace(p?.Title)) plist.AddItem(p!.Title);
            }
        }

        // Findings
        var assessments = (registration.Assessments ?? Array.Empty<DomainDetective.Assessment>()).ToList();
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

        // Evidence
        if (scope == ReportScope.Detailed)
        {
            if (current?.NameServers != null && current.NameServers.Count > 0)
            {
                headings.AddItem("Name servers", baseLevel);
                var ns = current.NameServers.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
                var nst = doc.AddTable(ns.Count + 1, 1, WordTableStyle.TableGrid);
                nst.Rows[0].Cells[0].AddParagraph("NameServer");
                for (int i = 0; i < ns.Count; i++)
                {
                    nst.Rows[i + 1].Cells[0].AddParagraph(ns[i]);
                }
            }

            if (current?.Status != null && current.Status.Count > 0)
            {
                headings.AddItem("RDAP status", baseLevel);
                var st = current.Status.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
                var stt = doc.AddTable(st.Count + 1, 1, WordTableStyle.TableGrid);
                stt.Rows[0].Cells[0].AddParagraph("Status");
                for (int i = 0; i < st.Count; i++)
                {
                    stt.Rows[i + 1].Cells[0].AddParagraph(st[i]);
                }
            }

            if (registration.Drift?.Changes != null && registration.Drift.Changes.Count > 0)
            {
                headings.AddItem("Structured drift", baseLevel);
                doc.AddParagraph("Structured changes between the latest two snapshots:");
                var changesList = registration.Drift.Changes;
                var dt = doc.AddTable(changesList.Count + 1, 5, WordTableStyle.TableGrid);
                dt.Rows[0].Cells[0].AddParagraph("Change");
                dt.Rows[0].Cells[1].AddParagraph("Before");
                dt.Rows[0].Cells[2].AddParagraph("After");
                dt.Rows[0].Cells[3].AddParagraph("Added");
                dt.Rows[0].Cells[4].AddParagraph("Removed");
                for (int i = 0; i < changesList.Count; i++)
                {
                    var c = changesList[i];
                    dt.Rows[i + 1].Cells[0].AddParagraph(c.Kind.ToString());
                    dt.Rows[i + 1].Cells[1].AddParagraph(c.Before ?? string.Empty);
                    dt.Rows[i + 1].Cells[2].AddParagraph(c.After ?? string.Empty);
                    dt.Rows[i + 1].Cells[3].AddParagraph(c.Added != null && c.Added.Count > 0 ? string.Join(", ", c.Added.Take(20)) + (c.Added.Count > 20 ? ", …" : "") : string.Empty);
                    dt.Rows[i + 1].Cells[4].AddParagraph(c.Removed != null && c.Removed.Count > 0 ? string.Join(", ", c.Removed.Take(20)) + (c.Removed.Count > 20 ? ", …" : "") : string.Empty);
                }
            }
        }

        // References
        if (registration.References != null && registration.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            doc.AddParagraph("Further reading and relevant standards.");
            WordLinkHelpers.AddReferencesList(doc, registration.References);
        }
    }
}

