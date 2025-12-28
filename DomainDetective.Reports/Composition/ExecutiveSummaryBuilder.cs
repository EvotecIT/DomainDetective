using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Single source of truth for Executive Summary rows across all renderers
/// (Word, Markdown, MarkdownHtml, HTML, Excel). Converts CompositionBuilder
/// domain buckets into canonical summary rows.
/// </summary>
public static class ExecutiveSummaryBuilder
{
    public sealed class Row
    {
        public string Domain { get; }
        public string Mx { get; }
        public string Spf { get; }
        public string Dkim { get; }
        public string Dmarc { get; }
        public string Mtasts { get; }
        public string TlsRpt { get; }
        public string Dnssec { get; }
        public string Rpki { get; }
        public string Classification { get; }
        public int Warnings { get; }
        public int Errors { get; }

        public Row(string domain, string mx, string spf, string dkim, string dmarc, string mtasts, string tlsRpt, string dnssec, string rpki, string classification, int warnings, int errors)
        {
            Domain = domain; Mx = mx; Spf = spf; Dkim = dkim; Dmarc = dmarc; Mtasts = mtasts; TlsRpt = tlsRpt; Dnssec = dnssec; Rpki = rpki; Classification = classification; Warnings = warnings; Errors = errors;
        }
    }

    public static List<Row> Build(IReadOnlyList<object> items, DomainOrder order, bool includeExtras = true)
    {
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));

        var grouped = CompositionBuilder.GroupBySubject(items);
        var ordered = CompositionBuilder.OrderDomains(items, grouped, order);
        var rows = new List<Row>(ordered.Count);

        foreach (var kv in ordered)
        {
            var d = kv.Key; var b = kv.Value;
            // Sum all core sections for parity with Word's overview: MX, SPF, DKIM, DMARC, ARC, BIMI, MTA-STS, TLS-RPT,
            // DNSBL, RPKI, Classification, DNSSEC, DANE, NS, SOA, ZoneTransfer, Wildcard, CAA, and MailTLS protocols.
            int warn = 0, err = 0;
            warn += b.Mx?.WarningCount ?? 0; err += b.Mx?.ErrorCount ?? 0;
            warn += b.Spf?.WarningCount ?? 0; err += b.Spf?.ErrorCount ?? 0;
            warn += b.Dmarc?.WarningCount ?? 0; err += b.Dmarc?.ErrorCount ?? 0;
            warn += b.Dkim?.Sum(x => x.WarningCount) ?? 0; err += b.Dkim?.Sum(x => x.ErrorCount) ?? 0;
            warn += b.Arc?.WarningCount ?? 0; err += b.Arc?.ErrorCount ?? 0;
            warn += b.Bimi?.WarningCount ?? 0; err += b.Bimi?.ErrorCount ?? 0;
            // Optional sections
            warn += b.Mtasts?.WarningCount ?? 0; err += b.Mtasts?.ErrorCount ?? 0;
            warn += b.TlsRpt?.WarningCount ?? 0; err += b.TlsRpt?.ErrorCount ?? 0;
            warn += b.Dnsbl?.WarningCount ?? 0; err += b.Dnsbl?.ErrorCount ?? 0;
            warn += b.Rpki?.WarningCount ?? 0; err += b.Rpki?.ErrorCount ?? 0;
            warn += b.Classification?.WarningCount ?? 0; err += b.Classification?.ErrorCount ?? 0;
            warn += b.Dnssec?.WarningCount ?? 0; err += b.Dnssec?.ErrorCount ?? 0;
            warn += b.Dane?.WarningCount ?? 0; err += b.Dane?.ErrorCount ?? 0;
            warn += b.Ns?.WarningCount ?? 0; err += b.Ns?.ErrorCount ?? 0;
            warn += b.Soa?.WarningCount ?? 0; err += b.Soa?.ErrorCount ?? 0;
            warn += b.ZoneTransfer?.WarningCount ?? 0; err += b.ZoneTransfer?.ErrorCount ?? 0;
            warn += b.Wildcard?.WarningCount ?? 0; err += b.Wildcard?.ErrorCount ?? 0;
            warn += b.Caa?.WarningCount ?? 0; err += b.Caa?.ErrorCount ?? 0;
            warn += b.Ttl?.WarningCount ?? 0; err += b.Ttl?.ErrorCount ?? 0;
            // Mail TLS trio
            warn += (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0);
            err  += (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0);
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: includeExtras);

            var dnssec = DisplayFormatting.ComposeDnssecSummary(b.Dnssec);
            var rpki = DisplayFormatting.ComposeRpkiSummary(b.Rpki);

            rows.Add(new Row(
                d,
                status(b.Mx?.Status),
                status(b.Spf?.Status),
                dkimStatus,
                status(b.Dmarc?.Status),
                status(b.Mtasts?.Status),
                status(b.TlsRpt?.Status),
                dnssec,
                rpki,
                status(b.Classification?.Classification),
                warn,
                err
            ));
        }

        return rows;
    }
}
