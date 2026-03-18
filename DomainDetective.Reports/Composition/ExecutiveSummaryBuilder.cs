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
        public string Microsoft365 { get; }
        public string Microsoft365Workloads { get; }
        public string Classification { get; }
        public int Warnings { get; }
        public int Errors { get; }

        public Row(string domain, string mx, string spf, string dkim, string dmarc, string mtasts, string tlsRpt, string dnssec, string rpki, string microsoft365, string microsoft365Workloads, string classification, int warnings, int errors)
        {
            Domain = domain; Mx = mx; Spf = spf; Dkim = dkim; Dmarc = dmarc; Mtasts = mtasts; TlsRpt = tlsRpt; Dnssec = dnssec; Rpki = rpki; Microsoft365 = microsoft365; Microsoft365Workloads = microsoft365Workloads; Classification = classification; Warnings = warnings; Errors = errors;
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
            warn += b.DnsAmplification?.WarningCount ?? 0; err += b.DnsAmplification?.ErrorCount ?? 0;
            warn += b.DnsOverTls?.WarningCount ?? 0; err += b.DnsOverTls?.ErrorCount ?? 0;
            warn += b.Microsoft365?.WarningCount ?? 0; err += b.Microsoft365?.ErrorCount ?? 0;
            // Mail TLS trio
            warn += (b.SmtpTls?.WarningCount ?? 0) + (b.ImapTls?.WarningCount ?? 0) + (b.PopTls?.WarningCount ?? 0);
            err  += (b.SmtpTls?.ErrorCount ?? 0) + (b.ImapTls?.ErrorCount ?? 0) + (b.PopTls?.ErrorCount ?? 0);
            string status(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s!;
            string dkimStatus = DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: includeExtras);

            var dnssec = DisplayFormatting.ComposeDnssecSummary(b.Dnssec);
            var rpki = DisplayFormatting.ComposeRpkiSummary(b.Rpki);
            var microsoft365Workloads = BuildMicrosoft365WorkloadSummary(b.Microsoft365);

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
                status(b.Microsoft365?.Status),
                microsoft365Workloads,
                status(b.Classification?.Classification),
                warn,
                err
            ));
        }

        return rows;
    }

    private static string BuildMicrosoft365WorkloadSummary(DomainDetective.Views.Microsoft365TenantInfo? microsoft365)
    {
        if (microsoft365 == null)
        {
            return "-";
        }

        var summary = microsoft365.WorkloadSummary ?? new DomainDetective.Microsoft365WorkloadConfidenceSummary();
        var segments = new List<string>();

        if (summary.StrongCount > 0)
        {
            segments.Add("Strong " + summary.StrongCount);
        }

        if (summary.ModerateCount > 0)
        {
            segments.Add("Moderate " + summary.ModerateCount);
        }

        if (summary.WeakCount > 0)
        {
            segments.Add("Weak " + summary.WeakCount);
        }

        if (segments.Count > 0)
        {
            var sourceSummary = BuildMicrosoft365WorkloadEvidenceSummary(microsoft365.Services);
            return string.IsNullOrWhiteSpace(sourceSummary)
                ? string.Join(", ", segments)
                : string.Join(", ", segments) + " [" + sourceSummary + "]";
        }

        var detectedCount = microsoft365.Services?.Count(static service => service.Status == DomainDetective.Microsoft365DetectionStatus.Detected) ?? 0;
        return detectedCount > 0 ? "Detected " + detectedCount : "-";
    }

    private static string BuildMicrosoft365WorkloadEvidenceSummary(IReadOnlyList<DomainDetective.Microsoft365ServiceDetection>? services)
    {
        if (services == null || services.Count == 0)
        {
            return string.Empty;
        }

        var detected = services
            .Where(static service => service.Status == DomainDetective.Microsoft365DetectionStatus.Detected)
            .ToList();
        if (detected.Count == 0)
        {
            return string.Empty;
        }

        var segments = detected
            .Where(static service => service.EvidenceSource != DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown)
            .GroupBy(static service => service.EvidenceSource)
            .OrderBy(static group => GetMicrosoft365WorkloadEvidenceSortOrder(group.Key))
            .ThenBy(static group => group.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Select(group => FormatMicrosoft365WorkloadEvidenceSource(group.Key) + " " + group.Count())
            .ToList();

        var boosted = detected.Count(static service => service.TenantContextBoosted);
        if (boosted > 0)
        {
            segments.Add("Boosted " + boosted);
        }

        return segments.Count == 0 ? string.Empty : string.Join(", ", segments);
    }

    private static int GetMicrosoft365WorkloadEvidenceSortOrder(DomainDetective.Microsoft365ServiceEvidenceSourceKind source)
    {
        switch (source)
        {
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.IdentityProbe:
                return 0;
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.MailProtocol:
                return 1;
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.KnownSubdomain:
                return 2;
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.DnsApplication:
                return 3;
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown:
            default:
                return int.MaxValue;
        }
    }

    private static string FormatMicrosoft365WorkloadEvidenceSource(DomainDetective.Microsoft365ServiceEvidenceSourceKind source)
    {
        switch (source)
        {
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.IdentityProbe:
                return "Identity";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.MailProtocol:
                return "Mail/Protocol";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.KnownSubdomain:
                return "Subdomain";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.DnsApplication:
                return "DNS App";
            case DomainDetective.Microsoft365ServiceEvidenceSourceKind.Unknown:
            default:
                return "Unknown";
        }
    }
}
