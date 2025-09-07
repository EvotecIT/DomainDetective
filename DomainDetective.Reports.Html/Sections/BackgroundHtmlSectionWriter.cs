using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports.Html;

public static class BackgroundHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, IReadOnlyList<object> items)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (items == null || items.Count == 0) return;

        html.AddHeading("Background", 2);

        var spf = items.OfType<DomainDetective.Views.SpfRecordInfo>().FirstOrDefault();
        if (spf?.Narrative != null)
        {
            html.AddHeading("SPF Overview", 3);
            if (!string.IsNullOrWhiteSpace(spf.Narrative.Introduction)) html.AddParagraph(spf.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(spf.Narrative.WhyItMatters)) html.AddParagraph(spf.Narrative.WhyItMatters);
        }

        var dkim = items.OfType<DomainDetective.Views.DkimRecordInfo>().FirstOrDefault();
        if (dkim?.Narrative != null)
        {
            html.AddHeading("DKIM Overview", 3);
            if (!string.IsNullOrWhiteSpace(dkim.Narrative.Introduction)) html.AddParagraph(dkim.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(dkim.Narrative.WhyItMatters)) html.AddParagraph(dkim.Narrative.WhyItMatters);
        }

        var dmarc = items.OfType<DomainDetective.Views.DmarcRecordInfo>().FirstOrDefault();
        if (dmarc?.Narrative != null)
        {
            html.AddHeading("DMARC Overview", 3);
            if (!string.IsNullOrWhiteSpace(dmarc.Narrative.Introduction)) html.AddParagraph(dmarc.Narrative.Introduction);
            if (!string.IsNullOrWhiteSpace(dmarc.Narrative.WhyItMatters)) html.AddParagraph(dmarc.Narrative.WhyItMatters);
        }

        if (items.OfType<DomainDetective.Views.MxInfo>().Any())
        {
            html.AddHeading("MX Overview", 3);
            html.AddParagraph("MX records direct inbound mail to the correct servers; multiple preferences improve resilience.");
        }

        if (items.OfType<DomainDetective.Views.MtastsInfo>().Any() || items.OfType<DomainDetective.Views.TlsRptInfo>().Any())
        {
            html.AddHeading("Transport Policies", 3);
            if (items.OfType<DomainDetective.Views.MtastsInfo>().Any()) html.AddParagraph("MTA-STS requires TLS for inbound mail using a published policy.");
            if (items.OfType<DomainDetective.Views.TlsRptInfo>().Any()) html.AddParagraph("TLS-RPT provides feedback reports about TLS failures.");
        }
    }
}

