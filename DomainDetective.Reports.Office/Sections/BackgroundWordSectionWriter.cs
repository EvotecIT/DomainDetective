using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Renders a single Background section with overview narratives to avoid per-domain duplication.
/// </summary>
public static class BackgroundWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, IReadOnlyList<object> items)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (headings == null) throw new ArgumentNullException(nameof(headings));
        if (items == null || items.Count == 0) return;

        headings.AddItem("Background");

        // SPF Overview
        var spf = items.OfType<DomainDetective.Views.SpfRecordInfo>().FirstOrDefault();
        if (spf != null && spf.Narrative != null)
        {
            headings.AddItem("SPF Overview", baseLevel);
            if (!string.IsNullOrWhiteSpace(spf.Narrative.Introduction)) doc.AddParagraph(spf.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(spf.Narrative.WhyItMatters)) doc.AddParagraph(spf.Narrative.WhyItMatters);

            // Mechanism meanings table for quick reference
            var types = new[] { "a", "mx", "ip4", "ip6", "include", "exists", "ptr", "redirect", "all", "version" };
            var t = doc.AddTable(types.Length + 1, 2, WordTableStyle.TableGrid);
            t.Rows[0].Cells[0].AddParagraph("Type");
            t.Rows[0].Cells[1].AddParagraph("Meaning");
            int r = 1;
            foreach (var ty in types)
            {
                t.Rows[r].Cells[0].AddParagraph(ty);
                t.Rows[r].Cells[1].AddParagraph(SpfMeaning(ty));
                r++;
            }
        }

        // DKIM Overview
        var dkim = items.OfType<DomainDetective.Views.DkimRecordInfo>().FirstOrDefault();
        if (dkim != null && dkim.Narrative != null)
        {
            headings.AddItem("DKIM Overview", baseLevel);
            if (!string.IsNullOrWhiteSpace(dkim.Narrative.Introduction)) doc.AddParagraph(dkim.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(dkim.Narrative.WhyItMatters)) doc.AddParagraph(dkim.Narrative.WhyItMatters);
        }

        // DMARC Overview
        var dmarc = items.OfType<DomainDetective.Views.DmarcRecordInfo>().FirstOrDefault();
        if (dmarc != null && dmarc.Narrative != null)
        {
            headings.AddItem("DMARC Overview", baseLevel);
            if (!string.IsNullOrWhiteSpace(dmarc.Narrative.Introduction)) doc.AddParagraph(dmarc.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(dmarc.Narrative.WhyItMatters)) doc.AddParagraph(dmarc.Narrative.WhyItMatters);
        }

        // MX Overview (generic narrative)
        var hasMx = items.OfType<DomainDetective.Views.MxInfo>().Any();
        if (hasMx)
        {
            headings.AddItem("MX Overview", baseLevel);
            doc.AddParagraph("Mail Exchanger (MX) records direct where inbound mail should be delivered and influence reliability and resilience.");
            doc.AddParagraph("Use multiple MX preferences and ensure consistency across name servers to avoid delivery issues.");
        }

        // Transport Policies Overview
        var hasMtasts = items.OfType<DomainDetective.Views.MtastsInfo>().Any();
        var hasTlsRpt = items.OfType<DomainDetective.Views.TlsRptInfo>().Any();
        if (hasMtasts || hasTlsRpt)
        {
            headings.AddItem("Transport Policies", baseLevel);
            if (hasMtasts) doc.AddParagraph("MTA-STS lets a domain require TLS for inbound mail and publish a policy over HTTPS.");
            if (hasTlsRpt) doc.AddParagraph("TLS-RPT enables receivers to send reports about TLS negotiation failures to help identify misconfigurations.");
        }
    }

    private static string SpfMeaning(string type)
    {
        switch (type)
        {
            case "a": return "Authorize host A/AAAA addresses.";
            case "mx": return "Authorize hosts listed as MX.";
            case "ip4": return "Authorize IPv4 address or CIDR block.";
            case "ip6": return "Authorize IPv6 address or CIDR block.";
            case "include": return "Import another domain's SPF policy.";
            case "exists": return "Authorize based on existence of DNS record.";
            case "ptr": return "Authorize hosts by PTR (discouraged).";
            case "redirect": return "Redirect evaluation to another domain.";
            case "all": return "Catch‑all for remaining senders.";
            case "version": return "SPF version token (v=spf1).";
            default: return "SPF token present.";
        }
    }
}

