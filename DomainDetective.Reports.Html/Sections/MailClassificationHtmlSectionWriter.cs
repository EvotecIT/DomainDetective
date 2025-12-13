using System;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HTML writer for Mail Classification section.
/// </summary>
public static class MailClassificationHtmlSectionWriter
{
    public static void Write(IHtmlComposer html, DomainDetective.Views.MailClassificationInfo info, string domain, Reports.ReportScope scope)
    {
        if (html == null) throw new ArgumentNullException(nameof(html));
        if (info == null) throw new ArgumentNullException(nameof(info));

        html.AddHeading($"Mail Classification — {domain}", 2);
        html.AddTable(new [] {
            new { Name = "Classification", Value = info.Classification },
            new { Name = "Confidence", Value = info.Confidence },
            new { Name = "Score", Value = info.Score.ToString("0.##") },
            new { Name = "Status", Value = info.Status },
            new { Name = "Primary Provider", Value = info.ProviderPrimary ?? string.Empty },
            new { Name = "Gateways", Value = (info.ProviderGateways != null && info.ProviderGateways.Count > 0) ? string.Join(", ", info.ProviderGateways) : string.Empty },
            new { Name = "Outbound Senders", Value = (info.ProviderOutbound != null && info.ProviderOutbound.Count > 0) ? string.Join(", ", info.ProviderOutbound) : string.Empty }
        });
    }
}
