using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: MailTLS sources footnote parity with Word.
/// </summary>
public static partial class HtmlCompositionReport
{
    private static void RenderMailTlsFootnote(Element page, List<KeyValuePair<string, DomainBucket>> ordered)
    {
        bool any = ordered.Any(kv => kv.Value.SmtpTls != null || kv.Value.ImapTls != null || kv.Value.PopTls != null);
        if (!any)
        {
            return;
        }

        page.Row(r => r.Column(TablerColumnNumber.Twelve, c => {
            c.Card(card => {
                card.Header(h => h.Title("MailTLS rollup sources by domain").Subtitle("Protocol shown in parentheses"));
                card.Body(b => {
                    foreach (var kv in ordered)
                    {
                        var d = kv.Key; var x = kv.Value;
                        string smtp = x.SmtpTls?.Status ?? "-";
                        string imap = x.ImapTls?.Status ?? "-";
                        string pop = x.PopTls?.Status ?? "-";
                        b.Text($"{d}: SMTP={smtp}, IMAP={imap}, POP={pop}");
                    }
                });
            });
        }));
    }
}

