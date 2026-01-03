using System;
using System.Linq;
using OfficeIMO.Word;
using DomainDetective.Providers.Email;
using DomainDetective.Providers.Dns;

namespace DomainDetective.Reports.Office;

public static class DnsInventoryWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, DomainDetective.Views.DnsInventoryInfo inv, string domain, ReportScope scope, bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (inv == null) throw new ArgumentNullException(nameof(inv));

        var dto = DomainDetective.Reports.SectionProjectors.BuildDnsInventory(inv);
        if (dto != null)
        {
            Write(doc, headings, baseLevel, dto, inv, domain, scope, showInfoFindings);
            return;
        }

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("DNS inventory section could not be projected.");
    }

    /// <summary>
    /// Projector-aware overload using SectionProjectors.DnsInventorySection.
    /// </summary>
    public static void Write(
        WordDocument doc,
        WordList headings,
        int baseLevel,
        DomainDetective.Reports.SectionProjectors.DnsInventorySection sec,
        DomainDetective.Views.DnsInventoryInfo? original,
        string domain,
        ReportScope scope,
        bool showInfoFindings)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (sec == null) throw new ArgumentNullException(nameof(sec));

        headings.AddItem("Summary", baseLevel);
        doc.AddParagraph("Inventory of common DNS records and TTLs for the domain apex.");

        var rows = sec.Summary.Count > 0 ? sec.Summary : new System.Collections.Generic.List<(string, string)> { ("Status", sec.Status) };
        var t = doc.AddTable(rows.Count, 2, WordTableStyle.TableGrid);
        for (int i = 0; i < rows.Count; i++)
        {
            t.Rows[i].Cells[0].AddParagraph(rows[i].Item1);
            t.Rows[i].Cells[1].AddParagraph(rows[i].Item2);
        }

        if (original != null && (original.Provider != DnsProvider.Unknown || (original.ProviderEvidence != null && original.ProviderEvidence.Count > 0)))
        {
            headings.AddItem("Inferred DNS Provider", baseLevel);
            doc.AddParagraph(original.Provider != DnsProvider.Unknown ? original.Provider.ToString() : "-");
            if (original.ProviderEvidence != null && original.ProviderEvidence.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var e in original.ProviderEvidence.Take(10))
                {
                    if (!string.IsNullOrWhiteSpace(e)) list.AddItem(e);
                }
                if (original.ProviderEvidence.Count > 10)
                {
                    doc.AddParagraph($"+{original.ProviderEvidence.Count - 10} more evidence item(s).").SetItalic(true);
                }
            }
        }

        if (original != null && (original.MailProvider != MailProviderKind.Unknown || (original.MailProviderEvidence != null && original.MailProviderEvidence.Count > 0)))
        {
            headings.AddItem("Inferred Mail Provider", baseLevel);
            doc.AddParagraph(original.MailProvider != MailProviderKind.Unknown ? original.MailProvider.ToString() : "-");
            if (original.MailProviderEvidence != null && original.MailProviderEvidence.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var e in original.MailProviderEvidence.Take(10))
                {
                    if (!string.IsNullOrWhiteSpace(e))
                    {
                        list.AddItem(e);
                    }
                }
                if (original.MailProviderEvidence.Count > 10)
                {
                    doc.AddParagraph($"+{original.MailProviderEvidence.Count - 10} more evidence item(s).").SetItalic(true);
                }
            }
        }

        if (original != null && (original.CnameTargetProvider != DnsCnameTargetProvider.Unknown ||
                                 original.CnameTargetFlags != DnsCnameTargetFlags.None ||
                                 (original.CnameTargetEvidence != null && original.CnameTargetEvidence.Count > 0)))
        {
            headings.AddItem("Apex CNAME Insight", baseLevel);
            doc.AddParagraph($"Provider: {(original.CnameTargetProvider != DnsCnameTargetProvider.Unknown ? original.CnameTargetProvider.ToString() : "-")}");
            doc.AddParagraph($"Flags: {(original.CnameTargetFlags != DnsCnameTargetFlags.None ? original.CnameTargetFlags.ToString() : "-")}");
            if (original.CnameTargetEvidence != null && original.CnameTargetEvidence.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var e in original.CnameTargetEvidence.Take(10))
                {
                    if (!string.IsNullOrWhiteSpace(e))
                    {
                        list.AddItem(e);
                    }
                }
                if (original.CnameTargetEvidence.Count > 10)
                {
                    doc.AddParagraph($"+{original.CnameTargetEvidence.Count - 10} more evidence item(s).").SetItalic(true);
                }
            }
        }

        if (original != null && (original.TxtSignals != DnsTxtSignals.None || (original.TxtSignalsEvidence != null && original.TxtSignalsEvidence.Count > 0)))
        {
            headings.AddItem("TXT Signals", baseLevel);
            doc.AddParagraph(original.TxtSignals != DnsTxtSignals.None ? original.TxtSignals.ToString() : "-");
            if (original.TxtSignalsEvidence != null && original.TxtSignalsEvidence.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var e in original.TxtSignalsEvidence.Take(10))
                {
                    if (!string.IsNullOrWhiteSpace(e))
                    {
                        list.AddItem(e);
                    }
                }
                if (original.TxtSignalsEvidence.Count > 10)
                {
                    doc.AddParagraph($"+{original.TxtSignalsEvidence.Count - 10} more evidence item(s).").SetItalic(true);
                }
            }
        }

        if (original != null && (original.CaaIssuers != DnsCaaIssuers.None || (original.CaaIssuersEvidence != null && original.CaaIssuersEvidence.Count > 0)))
        {
            headings.AddItem("CAA Issuers", baseLevel);
            doc.AddParagraph(original.CaaIssuers != DnsCaaIssuers.None ? original.CaaIssuers.ToString() : "-");
            if (original.CaaIssuersEvidence != null && original.CaaIssuersEvidence.Count > 0)
            {
                var list = doc.AddList(WordListStyle.Bulleted);
                foreach (var e in original.CaaIssuersEvidence.Take(10))
                {
                    if (!string.IsNullOrWhiteSpace(e))
                    {
                        list.AddItem(e);
                    }
                }
                if (original.CaaIssuersEvidence.Count > 10)
                {
                    doc.AddParagraph($"+{original.CaaIssuersEvidence.Count - 10} more evidence item(s).").SetItalic(true);
                }
            }
        }

        if (original != null && original.Queries != null && original.Queries.Count > 0)
        {
            headings.AddItem("Query Results", baseLevel);
            var q = original.Queries.OrderBy(x => x.RecordType).ToList();
            var qt = doc.AddTable(q.Count + 1, 5, WordTableStyle.TableGrid);
            qt.Rows[0].Cells[0].AddParagraph("Record Type");
            qt.Rows[0].Cells[1].AddParagraph("Status");
            qt.Rows[0].Cells[2].AddParagraph("Response");
            qt.Rows[0].Cells[3].AddParagraph("Records");
            qt.Rows[0].Cells[4].AddParagraph("Failure");
            for (int i = 0; i < q.Count; i++)
            {
                var r = q[i];
                qt.Rows[i + 1].Cells[0].AddParagraph(r.RecordType.ToString());
                qt.Rows[i + 1].Cells[1].AddParagraph(r.Status.ToString());
                qt.Rows[i + 1].Cells[2].AddParagraph(r.ResponseStatus.ToString());
                qt.Rows[i + 1].Cells[3].AddParagraph(r.Records.Count.ToString());
                var failureReason = r.FailureReason;
                string failureReasonText = string.IsNullOrWhiteSpace(failureReason) ? "-" : failureReason ?? "-";
                qt.Rows[i + 1].Cells[4].AddParagraph(failureReasonText);
            }
        }

        if (sec.Rows.Count > 0)
        {
            headings.AddItem("Captured Records (Sample)", baseLevel);
            int take = Math.Min(sec.Rows.Count, 200);
            var rt = doc.AddTable(take + 1, 6, WordTableStyle.TableGrid);
            rt.Rows[0].Cells[0].AddParagraph("Query");
            rt.Rows[0].Cells[1].AddParagraph("Section");
            rt.Rows[0].Cells[2].AddParagraph("Type");
            rt.Rows[0].Cells[3].AddParagraph("Name");
            rt.Rows[0].Cells[4].AddParagraph("TTL");
            rt.Rows[0].Cells[5].AddParagraph("Data");
            for (int i = 0; i < take; i++)
            {
                var r = sec.Rows[i];
                rt.Rows[i + 1].Cells[0].AddParagraph(r.QueryType.ToString());
                rt.Rows[i + 1].Cells[1].AddParagraph(r.Section.ToString());
                rt.Rows[i + 1].Cells[2].AddParagraph(r.RecordType.ToString());
                rt.Rows[i + 1].Cells[3].AddParagraph(r.Name);
                rt.Rows[i + 1].Cells[4].AddParagraph(r.Ttl.ToString());
                rt.Rows[i + 1].Cells[5].AddParagraph(r.Data);
            }

            if (sec.Rows.Count > take)
            {
                doc.AddParagraph($"Showing first {take} of {sec.Rows.Count} captured records.").SetItalic(true);
            }
        }

        var f = sec.Findings;
        if (!showInfoFindings) f = f.Where(x => !string.Equals(x.Severity, "Info", StringComparison.OrdinalIgnoreCase)).ToList();
        if (f.Count > 0)
        {
            headings.AddItem("Findings", baseLevel);
            var ft = doc.AddTable(f.Count + 1, 4, WordTableStyle.TableGrid);
            ft.Rows[0].Cells[0].AddParagraph("Severity");
            ft.Rows[0].Cells[1].AddParagraph("Code");
            ft.Rows[0].Cells[2].AddParagraph("Target");
            ft.Rows[0].Cells[3].AddParagraph("Message");
            for (int i = 0; i < f.Count; i++)
            {
                var a = f[i];
                ft.Rows[i + 1].Cells[0].AddParagraph(a.Severity);
                ft.Rows[i + 1].Cells[1].AddParagraph(a.Code);
                ft.Rows[i + 1].Cells[2].AddParagraph(a.Target);
                ft.Rows[i + 1].Cells[3].AddParagraph(a.Message);
            }
        }

        if (sec.References.Count > 0)
        {
            headings.AddItem("References", baseLevel);
            var list = doc.AddList(WordListStyle.Bulleted);
            foreach (var r in sec.References) if (!string.IsNullOrWhiteSpace(r)) list.AddItem(r);
        }
    }
}
