using System;
using System.Collections.Generic;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

internal static class ProviderHelpWordSectionWriter
{
    public static void Write(WordDocument doc, WordList headings, int baseLevel, IReadOnlyList<DomainDetective.Views.ProviderHelpLinks> help)
    {
        if (doc == null) throw new ArgumentNullException(nameof(doc));
        if (help == null || help.Count == 0) return;
        bool any = false;
        foreach (var h in help) { if (h != null && h.HasAny) { any = true; break; } }
        if (!any) return;

        headings.AddItem("Provider Help", baseLevel);
        doc.AddParagraph("Official provider documentation for configuring and troubleshooting core email controls:");

        foreach (var ph in help)
        {
            if (ph == null || !ph.HasAny) continue;
            doc.AddParagraph(ph.ProviderName).SetBold();
            var bl = doc.AddList(WordListStyle.Bulleted);
            if (!string.IsNullOrWhiteSpace(ph.Dmarc)) bl.AddItem($"DMARC: {ph.Dmarc}");
            if (!string.IsNullOrWhiteSpace(ph.Spf)) bl.AddItem($"SPF: {ph.Spf}");
            if (!string.IsNullOrWhiteSpace(ph.Dkim)) bl.AddItem($"DKIM: {ph.Dkim}");
            if (!string.IsNullOrWhiteSpace(ph.MtaSts)) bl.AddItem($"MTA-STS: {ph.MtaSts}");
            if (!string.IsNullOrWhiteSpace(ph.TlsRpt)) bl.AddItem($"TLS-RPT: {ph.TlsRpt}");
            if (!string.IsNullOrWhiteSpace(ph.Deliverability)) bl.AddItem($"Deliverability: {ph.Deliverability}");
        }
    }
}

