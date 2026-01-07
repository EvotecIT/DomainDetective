using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;

namespace DomainDetective.Reports.Office;

public static partial class ExcelCompositionReport
{
    // Adapter: map shared DomainBucket to local Excel DomainBucket structure
    private static DomainBucket Map(DomainDetective.Reports.CompositionBuilder.DomainBucket s)
    {
        var b = new DomainBucket {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            Arc = s.Arc,
            Bimi = s.Bimi,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            Dnsbl = s.Dnsbl,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            Ttl = s.Ttl,
            DesiredState = s.DesiredState,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls,
            Ns = s.Ns,
            Soa = s.Soa,
            Caa = s.Caa,
            Rpki = s.Rpki,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard,
            Classification = s.Classification,
            Subdomains = s.Subdomains,
            DnsInventory = s.DnsInventory,
            DnsTrace = s.DnsTrace,
            CtTimeline = s.CtTimeline,
            Http = s.Http,
            IpEnrichment = s.IpEnrichment,
            DnsAmplification = s.DnsAmplification,
            DnsOverTls = s.DnsOverTls
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        if (s.DnsPropagation != null && s.DnsPropagation.Count > 0) b.DnsPropagation.AddRange(s.DnsPropagation);
        return b;
    }

    private sealed class DomainBucket
    {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.ArcInfo? Arc { get; set; }
        public DomainDetective.Views.BimiRecordInfo? Bimi { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        public DomainDetective.Views.TtlInfo? Ttl { get; set; }
        public DomainDetective.Views.DesiredStateInfo? DesiredState { get; set; }
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.SubdomainsInfo? Subdomains { get; set; }
        public DomainDetective.Views.DnsInventoryInfo? DnsInventory { get; set; }
        public DomainDetective.Views.DnsTraceInfo? DnsTrace { get; set; }
        public DomainDetective.Views.CtTimelineInfo? CtTimeline { get; set; }
        public DomainDetective.Views.HttpInfo? Http { get; set; }
        public DomainDetective.Views.IpEnrichmentInfo? IpEnrichment { get; set; }
        public DomainDetective.Views.DnsAmplificationSummary? DnsAmplification { get; set; }
        public DomainDetective.Views.DnsOverTlsSummary? DnsOverTls { get; set; }
        public List<DomainDetective.Views.DnsPropagationInfo> DnsPropagation { get; } = new();
    }

    private static string MakeUniqueSheetName(string domain, HashSet<string> used)
    {
        string Sanitize(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return "Sheet";
            var invalid = new char[] { ':', '\\', '/', '?', '*', '[', ']' };
            var cleaned = new string(input.Where(ch => !invalid.Contains(ch)).ToArray());
            if (cleaned.Length > 31) cleaned = cleaned.Substring(0, 31);
            if (string.IsNullOrWhiteSpace(cleaned)) cleaned = "Sheet";
            return cleaned;
        }
        var baseName = Sanitize(domain);
        var name = baseName;
        int counter = 2;
        while (used.Contains(name))
        {
            var suffix = $" ({counter})";
            var trimmed = baseName;
            if (baseName.Length + suffix.Length > 31)
                trimmed = baseName.Substring(0, Math.Max(1, 31 - suffix.Length));
            name = trimmed + suffix;
            counter++;
        }
        used.Add(name);
        return name;
    }

    private struct RangeCoords { public int startCol, startRow, endCol, endRow; public RangeCoords(int sc, int sr, int ec, int er) { startCol = sc; startRow = sr; endCol = ec; endRow = er; } }
    private static RangeCoords ParseRange(string a1)
    {
        if (string.IsNullOrWhiteSpace(a1)) return default;
        var parts = a1.Split(':'); if (parts.Length != 2) return default;
        var (sc, sr) = A1ToCoord(parts[0]); var (ec, er) = A1ToCoord(parts[1]);
        if (sc <= 0 || sr <= 0 || ec <= 0 || er <= 0) return default;
        return new RangeCoords(Math.Min(sc, ec), Math.Min(sr, er), Math.Max(sc, ec), Math.Max(sr, er));
    }
    private static (int col, int row) A1ToCoord(string cell)
    {
        if (string.IsNullOrWhiteSpace(cell)) return (0, 0);
        int i = 0; int col = 0; while (i < cell.Length && char.IsLetter(cell[i])) { col = col * 26 + (char.ToUpperInvariant(cell[i]) - 'A' + 1); i++; }
        int row = 0; while (i < cell.Length && char.IsDigit(cell[i])) { row = row * 10 + (cell[i] - '0'); i++; }
        return (col, row);
    }
    private static string IndexToCol(int index)
    {
        if (index <= 0) return "A";
        string s = string.Empty; while (index > 0) { index--; s = (char)('A' + (index % 26)) + s; index /= 26; }
        return s;
    }
}
