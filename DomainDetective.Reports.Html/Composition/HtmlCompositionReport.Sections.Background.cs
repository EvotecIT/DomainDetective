using System;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: Background narrative section.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderBackgroundSection(Element page, System.Collections.Generic.IReadOnlyList<object> items)
    {
        if (items == null || items.Count == 0)
        {
            return;
        }

        var spf = items.OfType<DomainDetective.Views.SpfRecordInfo>().FirstOrDefault();
        var dkim = items.OfType<DomainDetective.Views.DkimRecordInfo>().FirstOrDefault();
        var dmarc = items.OfType<DomainDetective.Views.DmarcRecordInfo>().FirstOrDefault();
        bool hasMx = items.OfType<DomainDetective.Views.MxInfo>().Any();
        bool hasMtasts = items.OfType<DomainDetective.Views.MtastsInfo>().Any();
        bool hasTlsRpt = items.OfType<DomainDetective.Views.TlsRptInfo>().Any();

        bool hasNarrative =
            (spf?.Narrative != null) ||
            (dkim?.Narrative != null) ||
            (dmarc?.Narrative != null) ||
            hasMx || hasMtasts || hasTlsRpt;

        if (!hasNarrative)
        {
            return;
        }

        page.Row(r => r.Column(TablerColumnNumber.Twelve, c =>
        {
            c.Card(card =>
            {
                card.Header(h => h.Title("Background").Subtitle("Why these checks matter"));
                card.Body(b =>
                {
                    void AddSection(string title, params string?[] paragraphs)
                    {
                        var content = paragraphs.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p!.Trim()).ToList();
                        if (content.Count == 0)
                        {
                            return;
                        }
                        b.H4(title);
                        foreach (var p in content)
                        {
                            b.Text(p);
                        }
                    }

                    AddSection("SPF Overview",
                        spf?.Narrative?.Introduction,
                        spf?.Narrative?.WhyItMatters);

                    AddSection("DKIM Overview",
                        dkim?.Narrative?.Introduction,
                        dkim?.Narrative?.WhyItMatters);

                    AddSection("DMARC Overview",
                        dmarc?.Narrative?.Introduction,
                        dmarc?.Narrative?.WhyItMatters);

                    if (hasMx)
                    {
                        AddSection("MX Overview",
                            "MX records direct inbound mail to the correct servers; multiple preferences improve resilience.");
                    }

                    if (hasMtasts || hasTlsRpt)
                    {
                        var mtastsText = hasMtasts ? "MTA-STS requires TLS for inbound mail using a published policy." : null;
                        var tlsRptText = hasTlsRpt ? "TLS-RPT provides feedback reports about TLS failures." : null;
                        AddSection("Transport Policies", mtastsText, tlsRptText);
                    }
                });
            });
        }));
    }
}
