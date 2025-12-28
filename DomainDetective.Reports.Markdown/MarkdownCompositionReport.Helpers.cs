using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Narratives;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

public static partial class MarkdownCompositionReport {
    private static void RenderNarrative(MarkdownDoc md, NarrativeSections? narrative) {
        if (narrative == null) return;
        var intro = narrative.Introduction;
        var why = narrative.WhyItMatters;
        var details = narrative.Details?.Where(t => !string.IsNullOrWhiteSpace(t)).ToList() ?? new List<string>();
        var remediations = narrative.Remediations?.Where(t => !string.IsNullOrWhiteSpace(t)).ToList() ?? new List<string>();
        bool hasIntro = !string.IsNullOrWhiteSpace(intro);
        bool hasWhy = !string.IsNullOrWhiteSpace(why);
        if (!hasIntro && !hasWhy && details.Count == 0 && remediations.Count == 0) return;
        md.H3("Guidance");
        if (hasIntro) md.P(p => p.Bold("Summary: ").Text(intro!));
        if (hasWhy) md.P(p => p.Bold("Why it matters: ").Text(why!));
        if (details.Count > 0) {
            md.P(p => p.Bold("Details:"));
            md.Ul(details.ToArray());
        }
        if (remediations.Count > 0) {
            md.P(p => p.Bold("How to fix:"));
            md.Ul(remediations.ToArray());
        }
    }

    private static List<string> MergeReferences(IEnumerable<string>? first, IEnumerable<string>? second) {
        var list = new List<string>();
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(IEnumerable<string>? src) {
            if (src == null) return;
            foreach (var s in src) {
                if (string.IsNullOrWhiteSpace(s)) continue;
                if (set.Add(s)) list.Add(s);
            }
        }
        Add(first);
        Add(second);
        return list;
    }

    private static void RenderReferences(MarkdownDoc md, IEnumerable<string>? references) {
        if (references == null) return;
        var list = references.Where(u => !string.IsNullOrWhiteSpace(u)).ToList();
        if (list.Count == 0) return;
        md.H3("References");
        md.Ul(ul => {
            foreach (var u in list) {
                var f = LinkFormatter.Format(u);
                ul.ItemLink(f.Title, f.Url);
            }
        });
    }

    private static void RenderMailTlsServers(MarkdownDoc md, string title, DomainDetective.Views.MailTlsInfo info) {
        var servers = info.Servers;
        if (servers == null || servers.Count == 0) return;
        md.H4($"{title} Servers");
        var rows = servers.Select(s => (IReadOnlyList<string>)new string[] {
            s.Key,
            info.Status ?? "-",
            s.StartTlsAdvertised ? "Yes" : "No",
            s.Grade.ToString(),
            string.IsNullOrWhiteSpace(s.Protocol) ? "-" : s.Protocol,
            s.Tls13Used ? "Yes" : (s.SupportsTls13 ? "Supported" : "No"),
            s.CertificateValid ? "Valid" : "Invalid",
            s.ChainValid ? "Valid" : "Invalid",
            s.ValidTo.HasValue ? s.ValidTo.Value.ToString("yyyy-MM-dd") : "-",
            s.DaysToExpire.ToString(),
            string.IsNullOrWhiteSpace(s.CipherSuite) ? "-" : s.CipherSuite
        }).ToList();
        md.Table(t => t.Headers("Host","Status","StartTLS","Grade","Protocol","TLS 1.3","Cert","Chain","Expires","Days","Cipher")
            .Rows(rows)
            .AlignLeft(0,1,4,10)
            .AlignCenter(2,3,5,6,7,8,9));
    }
}
