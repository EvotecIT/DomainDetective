using System;
using System.Collections.Generic;
using System.Linq;
using HtmlForgeX;
using HtmlForgeX.Extensions;
using HtmlForgeX.Containers.Tabler;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Html;

/// <summary>
/// HtmlCompositionReport partial: helpers, models, and enums.
/// </summary>
public static partial class HtmlCompositionReport {
    private static string BuildSubjectTitle(List<string> domains)
        => CompositionBuilder.BuildSubjectTitle(domains);

    private static bool IsEmptyStatus(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        var v = value!.Trim();
        return v == "-" || v.Equals("n/a", StringComparison.OrdinalIgnoreCase);
    }

    private static void ConfigureAccordion(TablerAccordion acc, string? persistKey = null)
    {
        acc.Type(TablerAccordionType.Flush)
           .ItemHeaderSize(5)
           .FullWidthLines(true)
           .Settings(s => s
               .SingleOpenClosable(true)
               .PersistState(persistKey)
               .CopyTitleButtons()
               .Searchable()
               .SearchPlaceholder("Search (AND/OR/\"phrase\"/-NOT)")
               .SearchHelp()
               .End())
           .Color(TablerColor.Blue);
    }

    private static void ConfigureStandardDataTable(DataTablesTable table, ToggleViewMode defaultMode = ToggleViewMode.ScrollX)
    {
        if (table == null)
        {
            return;
        }

        table.Style(BootStrapTableStyle.Striped)
             .Style(BootStrapTableStyle.Hover)
             .EnableResponsive(opts => opts.InlineDetails());

        table.Settings(s =>
        {
            s.HeaderNaming(n => { n.Enabled = true; });
            s.ToggleViewButton("Switch View", defaultMode: defaultMode, persist: true);
            s.Preset(DataTablesPreset.MinimalWithExport);
            s.NullsAs("—");
            s.EnumFormatting(e => e.UseDisplay().UseDescription().SplitPascalCaseFallback(true));
        });
    }

    private static void AddGridPanelUnique(
        TablerDataGrid grid,
        HashSet<string> seenKeys,
        string key,
        string value,
        TablerColor? color = null,
        bool light = false)
    {
        if (grid == null)
        {
            return;
        }

        if (seenKeys == null)
        {
            throw new ArgumentNullException(nameof(seenKeys));
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        var normalized = key.Trim();
        if (!seenKeys.Add(normalized))
        {
            return;
        }

        var item = grid.AddItem(normalized, value ?? string.Empty);
        if (color.HasValue)
        {
            item.AsPanel(color.Value, light: light);
        }
        else
        {
            item.AsPanel();
        }
    }

    private static void AddGridSummaryPanelsUnique(
        TablerDataGrid grid,
        HashSet<string> seenKeys,
        IEnumerable<(string Key, string Value)> summary)
    {
        if (grid == null)
        {
            return;
        }

        if (seenKeys == null)
        {
            throw new ArgumentNullException(nameof(seenKeys));
        }

        if (summary == null)
        {
            return;
        }

        foreach (var kv in summary)
        {
            if (string.IsNullOrWhiteSpace(kv.Key))
            {
                continue;
            }

            var key = kv.Key.Trim();
            if (!seenKeys.Add(key))
            {
                continue;
            }

            grid.AddItem(key, kv.Value ?? string.Empty).AsPanel();
        }
    }

    private static (int warn, int err) CountFindings(DomainBucket b)      
    {
        if (b == null)
        {
            return (0, 0);
        }

        int warn = 0;
        int err = 0;

        static void Add(ref int warn, ref int err, int w, int e)
        {
            warn += w;
            err += e;
        }

        Add(ref warn, ref err, b.Mx?.WarningCount ?? 0, b.Mx?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Spf?.WarningCount ?? 0, b.Spf?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Dmarc?.WarningCount ?? 0, b.Dmarc?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Mtasts?.WarningCount ?? 0, b.Mtasts?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.TlsRpt?.WarningCount ?? 0, b.TlsRpt?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Dnsbl?.WarningCount ?? 0, b.Dnsbl?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Dnssec?.WarningCount ?? 0, b.Dnssec?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Dane?.WarningCount ?? 0, b.Dane?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Rpki?.WarningCount ?? 0, b.Rpki?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Ns?.WarningCount ?? 0, b.Ns?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Soa?.WarningCount ?? 0, b.Soa?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Caa?.WarningCount ?? 0, b.Caa?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Ttl?.WarningCount ?? 0, b.Ttl?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.ZoneTransfer?.WarningCount ?? 0, b.ZoneTransfer?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Wildcard?.WarningCount ?? 0, b.Wildcard?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Classification?.WarningCount ?? 0, b.Classification?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Arc?.WarningCount ?? 0, b.Arc?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.Bimi?.WarningCount ?? 0, b.Bimi?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.SmtpTls?.WarningCount ?? 0, b.SmtpTls?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.ImapTls?.WarningCount ?? 0, b.ImapTls?.ErrorCount ?? 0);
        Add(ref warn, ref err, b.PopTls?.WarningCount ?? 0, b.PopTls?.ErrorCount ?? 0);

        if (b.Dkim != null && b.Dkim.Count > 0)
        {
            foreach (var d in b.Dkim)
            {
                if (d == null)
                {
                    continue;
                }
                warn += d.WarningCount;
                err += d.ErrorCount;
            }
        }

        return (warn, err);
    }

    private sealed class FindingSummary
    {
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string? Code { get; set; }
        public string? Target { get; set; }
        public int Count { get; set; }
    }

    private static string TrimForDisplay(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        var t = text!.Trim();
        if (t.Length <= max) return t;
        return t.Substring(0, max - 1) + "...";
    }

    private static string? BuildProviderSummary(DomainDetective.Views.MailClassificationInfo? classification)
    {
        if (classification == null) return null;
        var primary = classification.ProviderPrimary;
        if (string.IsNullOrWhiteSpace(primary)) return null;
        var provider = primary!.Trim();
        if (classification.ProviderGateways != null && classification.ProviderGateways.Count > 0)
            provider += $" via {string.Join(", ", classification.ProviderGateways)}";
        if (classification.ProviderOutbound != null && classification.ProviderOutbound.Count > 0)
            provider += $"; outbound: {string.Join(", ", classification.ProviderOutbound)}";
        return $"Provider: {TrimForDisplay(provider, 160)}";
    }

    private static IEnumerable<DomainDetective.Assessment> EnumerateAssessments(DomainBucket b)
    {
        static IEnumerable<DomainDetective.Assessment> FromList(IReadOnlyList<DomainDetective.Assessment>? list)
        {
            if (list == null) yield break;
            foreach (var a in list)
            {
                if (a == null) continue;
                yield return a;
            }
        }

        foreach (var a in FromList(b.Mx?.Assessments)) yield return a;
        foreach (var a in FromList(b.Spf?.Assessments)) yield return a;
        foreach (var a in FromList(b.Dmarc?.Assessments)) yield return a;
        foreach (var a in FromList(b.Mtasts?.Assessments)) yield return a;
        foreach (var a in FromList(b.TlsRpt?.Assessments)) yield return a;
        foreach (var a in FromList(b.Dnsbl?.Assessments)) yield return a;
        foreach (var a in FromList(b.Ns?.Assessments)) yield return a;
        foreach (var a in FromList(b.Soa?.Assessments)) yield return a;
        foreach (var a in FromList(b.ZoneTransfer?.Assessments)) yield return a;
        foreach (var a in FromList(b.Wildcard?.Assessments)) yield return a;    
        foreach (var a in FromList(b.Ttl?.Assessments)) yield return a;
        foreach (var a in FromList(b.Dnssec?.Assessments)) yield return a;      
        foreach (var a in FromList(b.Dane?.Assessments)) yield return a;        
        foreach (var a in FromList(b.Caa?.Assessments)) yield return a;
        foreach (var a in FromList(b.Rpki?.Assessments)) yield return a;        
        foreach (var a in FromList(b.Classification?.Assessments)) yield return a;
        foreach (var a in FromList(b.Arc?.Assessments)) yield return a;
        foreach (var a in FromList(b.Bimi?.Assessments)) yield return a;
        foreach (var a in FromList(b.SmtpTls?.Assessments)) yield return a;
        foreach (var a in FromList(b.ImapTls?.Assessments)) yield return a;
        foreach (var a in FromList(b.PopTls?.Assessments)) yield return a;
        foreach (var dkim in b.Dkim)
        {
            foreach (var a in FromList(dkim?.Assessments)) yield return a;
        }
    }

    private static int SeverityRank(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity)) return 3;
        var s = severity!.Trim().ToLowerInvariant();
        if (s.Contains("error")) return 0;
        if (s.Contains("warning") || s.Contains("warn")) return 1;        
        return 2;
    }

    private static (TablerColor color, TablerIconType icon, string label) FindingAlertStyle(string? severity)
    {
        var rank = SeverityRank(severity);
        if (rank == 0)
        {
            return (TablerColor.Danger, TablerIconType.CircleX, "Error");
        }
        if (rank == 1)
        {
            return (TablerColor.Warning, TablerIconType.AlertTriangle, "Warning");
        }
        return (TablerColor.Info, TablerIconType.InfoCircle, "Info");
    }

    private static string? NormalizeFindingCodeForDisplay(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return null;
        }

        var c = code!.Trim();
        if (c.Length > 80)
        {
            return null;
        }

        if (c.IndexOf("DomainDetective", StringComparison.OrdinalIgnoreCase) >= 0
            || c.IndexOf("Assessment", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return null;
        }

        return c;
    }

    private static void RenderTopFindingsList(Element container, IReadOnlyList<FindingSummary> topFindings, bool includeCode)
    {
        if (topFindings == null || topFindings.Count == 0)
        {
            container.Text("No warnings or errors detected.").Style(TablerTextStyle.Muted);
            return;
        }

        foreach (var f in topFindings)
        {
            var (color, icon, label) = FindingAlertStyle(f.Severity);
            var message = TrimForDisplay(f.Title, 420);
            var metaParts = new List<string>
            {
                label,
                $"{f.Count} occurrence{(f.Count == 1 ? string.Empty : "s")}"
            };

            if (!string.IsNullOrWhiteSpace(f.Target))
            {
                metaParts.Add($"Target: {TrimForDisplay(f.Target, 160)}");
            }

            if (includeCode)
            {
                var code = NormalizeFindingCodeForDisplay(f.Code);
                if (!string.IsNullOrWhiteSpace(code))
                {
                    metaParts.Add($"Code: {code}");
                }
            }

            container.Alert(message, string.Join(" • ", metaParts), color)
                .Icon(icon)
                .Minor();
        }
    }

    private static List<FindingSummary> BuildTopFindings(IEnumerable<DomainBucket> buckets, int maxItems)
    {
        var map = new Dictionary<string, FindingSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in buckets ?? Array.Empty<DomainBucket>())
        {
            foreach (var a in EnumerateAssessments(b))
            {
                if (a == null) continue;
                if (a.Severity == DomainDetective.AssessmentSeverity.Info) continue;
                var sev = a.Severity.ToString();
                var title = !string.IsNullOrWhiteSpace(a.Message)
                    ? a.Message!
                    : (NormalizeFindingCodeForDisplay(a.Code) ?? "Finding");
                var code = string.IsNullOrWhiteSpace(a.Code) ? null : a.Code;
                var target = string.IsNullOrWhiteSpace(a.Target) ? null : a.Target;
                var key = $"{sev}|{code}|{title}";
                if (!map.TryGetValue(key, out var summary))
                {
                    summary = new FindingSummary { Title = title, Severity = sev, Code = code, Target = target, Count = 0 };
                    map[key] = summary;
                }
                summary.Count += 1;
            }
        }

        return map.Values
                  .OrderBy(s => SeverityRank(s.Severity))
                  .ThenByDescending(s => s.Count)
                  .ThenBy(s => s.Code ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                  .ThenBy(s => s.Title, StringComparer.OrdinalIgnoreCase)
                  .Take(Math.Max(1, maxItems))
                  .ToList();
    }

    private static Dictionary<string, (int ok, int warn, int err, int unknown)> BuildControlRollup(IEnumerable<DomainDetective.Reports.ExecutiveSummaryBuilder.Row> rows)
    {
        var controls = new Dictionary<string, (int ok, int warn, int err, int unknown)>(StringComparer.OrdinalIgnoreCase)
        {
            ["MX"] = (0,0,0,0),
            ["SPF"] = (0,0,0,0),
            ["DKIM"] = (0,0,0,0),
            ["DMARC"] = (0,0,0,0),
            ["MTA-STS"] = (0,0,0,0),
            ["TLS-RPT"] = (0,0,0,0),
            ["DNSSEC"] = (0,0,0,0),
            ["RPKI"] = (0,0,0,0)
        };

        static void Tally(ref (int ok, int warn, int err, int unknown) bucket, string? status)
        {
            var s = (status ?? "-").Trim().ToLowerInvariant();
            if (s.Contains("error") || s.Contains("fail")) { bucket.err++; return; }
            if (s.Contains("warn")) { bucket.warn++; return; }
            if (s == "-" || s.Contains("none") || s.Contains("missing")) { bucket.unknown++; return; }
            bucket.ok++;
        }

        foreach (var r in rows ?? Array.Empty<DomainDetective.Reports.ExecutiveSummaryBuilder.Row>())
        {
            var v = controls["MX"]; Tally(ref v, r.Mx); controls["MX"] = v;
            v = controls["SPF"]; Tally(ref v, r.Spf); controls["SPF"] = v;
            v = controls["DKIM"]; Tally(ref v, r.Dkim); controls["DKIM"] = v;
            v = controls["DMARC"]; Tally(ref v, r.Dmarc); controls["DMARC"] = v;
            v = controls["MTA-STS"]; Tally(ref v, r.Mtasts); controls["MTA-STS"] = v;
            v = controls["TLS-RPT"]; Tally(ref v, r.TlsRpt); controls["TLS-RPT"] = v;
            v = controls["DNSSEC"]; Tally(ref v, r.Dnssec); controls["DNSSEC"] = v;
            v = controls["RPKI"]; Tally(ref v, r.Rpki); controls["RPKI"] = v;
        }

        return controls;
    }

    private static string ComputeOverallGrade(IEnumerable<DomainDetective.Reports.ExecutiveSummaryBuilder.Row> rows)
    {
        if (rows == null) return "N/A";
        int warn = 0;
        int err = 0;
        foreach (var r in rows)
        {
            if (r == null) continue;
            warn += r.Warnings;
            err += r.Errors;
        }
        if (err == 0 && warn == 0) return "A";
        if (err == 0 && warn <= 3) return "B";
        if (err == 0 && warn <= 10) return "C";
        if (err <= 3) return "D";
        return "F";
    }

    private static TablerColor GradeColor(string grade)
    {
        switch ((grade ?? string.Empty).Trim().ToUpperInvariant())
        {
            case "A":
                return TablerColor.Green;
            case "B":
                return TablerColor.Teal;
            case "C":
                return TablerColor.Orange;
            case "D":
                return TablerColor.Red;
            case "F":
                return TablerColor.Red;
            default:
                return TablerColor.Blue;
        }
    }

    private static string ControlStatusLabel((int ok, int warn, int err, int unknown) rollup)
    {
        if (rollup.err > 0) return "Error";
        if (rollup.warn > 0) return "Warning";
        if (rollup.ok > 0) return "OK";
        return "Unknown";
    }

    private sealed class DomainBucket {
        public string Subject { get; set; } = string.Empty;
        public DomainDetective.Views.MxInfo? Mx { get; set; }
        public DomainDetective.Views.SpfRecordInfo? Spf { get; set; }
        public DomainDetective.Views.DmarcRecordInfo? Dmarc { get; set; }       
        public List<DomainDetective.Views.DkimRecordInfo> Dkim { get; } = new();
        public DomainDetective.Views.ArcInfo? Arc { get; set; }
        public DomainDetective.Views.BimiRecordInfo? Bimi { get; set; }
        public DomainDetective.Views.DnsblInfo? Dnsbl { get; set; }
        public DomainDetective.Views.MailClassificationInfo? Classification { get; set; }
        public DomainDetective.Views.MtastsInfo? Mtasts { get; set; }
        public DomainDetective.Views.TlsRptInfo? TlsRpt { get; set; }
        public DomainDetective.Views.NsInfo? Ns { get; set; }
        public DomainDetective.Views.SoaInfo? Soa { get; set; }
        public DomainDetective.Views.CaaInfo? Caa { get; set; }
        public DomainDetective.Views.DnssecStatusInfo? Dnssec { get; set; }
        public DomainDetective.Views.DaneRecordInfo? Dane { get; set; }
        public DomainDetective.Views.MailTlsInfo? SmtpTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? ImapTls { get; set; }
        public DomainDetective.Views.MailTlsInfo? PopTls { get; set; }
        public DomainDetective.Views.RpkiInfo? Rpki { get; set; }
        public DomainDetective.Views.ZoneTransferInfo? ZoneTransfer { get; set; }
        public DomainDetective.Views.WildcardDnsInfo? Wildcard { get; set; }
        public DomainDetective.Views.TtlInfo? Ttl { get; set; }
    }

    private static Dictionary<string, DomainBucket> GroupBySubject(IReadOnlyList<object> items)
    {
        var comp = CompositionBuilder.GroupBySubject(items);
        var map = new Dictionary<string, DomainBucket>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in comp)
        {
            map[kv.Key] = Map(kv.Value);
        }
        return map;
    }

    private static List<KeyValuePair<string, DomainBucket>> OrderDomainsByInput(IReadOnlyList<object> items, Dictionary<string, DomainBucket> grouped) {
        var comp = CompositionBuilder.GroupBySubject(items);
        var orderedComp = CompositionBuilder.OrderDomains(items, comp, DomainOrder.Input);
        var list = new List<KeyValuePair<string, DomainBucket>>();
        foreach (var kv in orderedComp)
        {
            if (grouped.TryGetValue(kv.Key, out var b)) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, b));
        }
        foreach (var kv in grouped.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            if (!list.Any(x => string.Equals(x.Key, kv.Key, StringComparison.OrdinalIgnoreCase))) list.Add(new KeyValuePair<string, DomainBucket>(kv.Key, kv.Value));
        return list;
    }

    private static Dictionary<string, List<string>> DetermineSectionOrderByDomain(IReadOnlyList<object> items) {
        return SectionOrdering.DetermineSectionOrderByDomain(items);
    }

    private static string[] CanonicalSections => SectionOrdering.CanonicalSections.ToArray();

    private static string[] NormalizeSectionList(IEnumerable<string> list) {    
        return SectionOrdering.NormalizeSectionList(list);
    }
    private static string NormalizeSection(string s) {
        return SectionOrdering.NormalizeSection(s);
    }

    // Helper: choose a badge color for a status string
    private static TablerBadgeColor ColorForStatus(string? status) {
        var s = (status ?? "-").Trim().ToLowerInvariant();
        if (s.Contains("error") || s.Contains("fail")) return TablerBadgeColor.Danger;
        if (s.Contains("warn")) return TablerBadgeColor.Warning;
        if (s.Contains("ok") || s.Contains("pass") || s.Contains("valid")) return TablerBadgeColor.Success;
        if (s == "-" || s.Contains("none") || s.Contains("missing")) return TablerBadgeColor.Info;
        return TablerBadgeColor.Blue;
    }

    private static TablerColor PanelColorForStatus(string? status)
    {
        var s = (status ?? "-").Trim().ToLowerInvariant();
        if (s.Contains("error") || s.Contains("fail")) return TablerColor.Red;
        if (s.Contains("warn")) return TablerColor.Orange;
        if (s.Contains("ok") || s.Contains("pass") || s.Contains("valid")) return TablerColor.Green;
        if (s == "-" || s.Contains("none") || s.Contains("missing")) return TablerColor.Blue;
        return TablerColor.Blue;
    }

    // Adapter: map shared CompositionBuilder.DomainBucket to the local DomainBucket used by HTML renderer
    private static DomainBucket Map(CompositionBuilder.DomainBucket s)
    {
        var b = new DomainBucket
        {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            Arc = s.Arc,
            Bimi = s.Bimi,
            Dnsbl = s.Dnsbl,
            Classification = s.Classification,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            Ns = s.Ns,
            Soa = s.Soa,
            Caa = s.Caa,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls,
            Rpki = s.Rpki,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard,
            Ttl = s.Ttl
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        return b;
    }
}
