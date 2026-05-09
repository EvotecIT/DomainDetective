using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport {
    private static Action<SheetComposer.ColumnComposer> BuildEmailAuthenticationOverviewBlock(DomainBucket bucket)
    {
        return column => column.Section("Email Authentication");
    }

    private static Action<SheetComposer.ColumnComposer>? BuildSpfBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Spf == null)
        {
            return null;
        }

        var spf = bucket.Spf;
        var projection = DomainDetective.Reports.SectionProjectors.BuildSpf(spf);

        return column =>
        {
            column.Section("SPF");

            var props = new List<(string, object?)>
            {
                ("Status", spf.Status ?? "-"),
                ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                ("DNS TTL (s)", spf.DnsRecordTtl?.ToString() ?? "-"),
                ("CNAME Resolved", spf.IsCnameResolved ? "Yes" : "No"),
                ("CNAME TTL (s)", spf.CnameTtl?.ToString() ?? "-"),
                ("DNS Lookups", projection?.DnsLookupsCount ?? spf.DnsLookupsCount)
            };

            if (!string.IsNullOrWhiteSpace(spf.Raw?.AllMechanism))
            {
                props.Add(("All Mechanism", spf.Raw!.AllMechanism!));
            }

            column.KeyValues(props);

            if ((projection?.Findings.Count ?? 0) > 0)
            {
                var rows = projection!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (!string.IsNullOrWhiteSpace(projection?.SpfRecord))
            {
                column.Section("Evidence").KeyValues(new (string, object?)[] { ("SPF Record", projection!.SpfRecord) });
            }

            if ((projection?.Mechanisms.Count ?? 0) > 0)
            {
                var mech = projection!.Mechanisms.Select(m => new { Prefix = m.Qualifier, Type = m.Type, Value = m.Value, Provider = m.Provider }).ToList();
                var range = column.TableFrom(mech, title: "Mechanisms", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Prefix");
                    opt.MediumHeaders.Add("Type");
                    opt.LongHeaders.Add("Value");
                    opt.WrapHeaders.Add("Value");
                });
            }

            if ((projection?.FlattenedUniqueIpCount ?? 0) + (projection?.FlattenedDuplicateIpCount ?? 0) + (projection?.FlattenedTokenCount ?? 0) > 0)
            {
                column.Section("Flattened IP Analysis").KeyValues(new (string, object?)[]
                {
                    ("Unique IPs", projection!.FlattenedUniqueIpCount),
                    ("Duplicate IPs", projection.FlattenedDuplicateIpCount),
                    ("Tokens Resolved", projection.FlattenedTokenCount)
                });
            }

            if ((projection?.ProviderHelp.Count ?? 0) > 0)
            {
                var list = projection!.ProviderHelp.Take(8)
                    .Select(t => string.IsNullOrWhiteSpace(t.Title) ? t.Url ?? string.Empty : t.Title!)
                    .ToArray();
                column.Section("Provider Help").BulletedList(list);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDkimBlock(SheetComposer composer, DomainBucket bucket)
    {
        if (bucket.Dkim == null || bucket.Dkim.Count == 0)
        {
            return null;
        }

        var projection = DomainDetective.Reports.SectionProjectors.BuildDkim(bucket.Dkim, bucket.Ttl);

        return column =>
        {
            column.Section("DKIM").KeyValues(new (string, object?)[]
            {
                ("Selectors", bucket.Dkim.Count),
                ("Any Weak", bucket.Dkim.Any(x => x.WeakKey) ? "Yes" : "No")
            });

            if (projection != null && projection.Rows.Count > 0)
            {
                var rows = projection.Rows.Select(r => new
                {
                    Selector = r.Selector,
                    Status = string.IsNullOrWhiteSpace(r.Status) ? "-" : r.Status,
                    KeyBits = string.IsNullOrWhiteSpace(r.KeyBits) ? "-" : r.KeyBits,
                    Alg = string.IsNullOrWhiteSpace(r.Hash) ? "-" : r.Hash,
                    Weak = r.Weak ? "Yes" : "No",
                    Flags = string.IsNullOrWhiteSpace(r.Flags) ? string.Empty : r.Flags,
                    TTL = r.TtlSeconds.HasValue ? r.TtlSeconds.Value.ToString() : "-",
                    CnameResolved = r.CnameResolved ? "Yes" : "No",
                    CnameTtl = r.CnameTtlSeconds?.ToString() ?? "-"
                }).ToList();
                var range = column.TableFrom(rows, title: "Selectors", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.UnionWith(new[] { "Status", "Weak", "Key Bits", "Alg", "TTL", "Cname Resolved", "Cname Ttl" });
                    opt.MediumHeaders.UnionWith(new[] { "Selector", "Flags" });
                });
            }

            if (projection != null && projection.Findings.Count > 0)
            {
                var rows = projection.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                var range = column.TableFrom(rows, title: "Findings", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.ShortHeaders.Add("Severity");
                    opt.MediumHeaders.UnionWith(new[] { "Code", "Target" });
                    opt.LongHeaders.Add("Message");
                    opt.WrapHeaders.Add("Message");
                });
            }

            if (projection != null && projection.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record)))
            {
                var rows = projection.Rows
                    .Where(r => !string.IsNullOrWhiteSpace(r.Record))
                    .Select(r => new { r.Selector, Record = r.Record })
                    .ToList();
                var range = column.TableFrom(rows, title: "Evidence", configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                composer.ApplyColumnSizing(range, opt =>
                {
                    opt.MediumHeaders.Add("Selector");
                    opt.LongHeaders.Add("Record");
                    opt.WrapHeaders.Add("Record");
                });
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildDmarcBlock(DomainBucket bucket)
    {
        if (bucket.Dmarc == null)
        {
            return null;
        }

        var d = bucket.Dmarc;
        return column =>
        {
            column.Section("DMARC").KeyValues(new (string, object?)[]
            {
                ("Record Present", d.DmarcRecordExists ? "Yes" : "No"),
                ("Starts Correctly", d.StartsCorrectly ? "Yes" : "No"),
                ("DNS TTL (s)", d.DnsRecordTtl?.ToString() ?? "-"),
                ("CNAME Resolved", d.IsCnameResolved ? "Yes" : "No"),
                ("CNAME TTL (s)", d.CnameTtl?.ToString() ?? "-"),
                ("Policy (p)", d.Policy ?? "-"),
                ("Subdomain Policy (sp)", d.SubPolicy ?? "-"),
                ("Percent (pct)", d.Percent ?? "-"),
                ("Alignment", $"dkim={d.DkimAlignment ?? "?"} / spf={d.SpfAlignment ?? "?"}"),
                ("Public Suffix Policy", string.IsNullOrWhiteSpace(d.PublicSuffixPolicy) ? "-" : d.PublicSuffixPolicy),
                ("Nonexistent Policy", string.IsNullOrWhiteSpace(d.NonexistentPolicy) ? "-" : d.NonexistentPolicy),
                ("Is Policy Valid", d.IsPolicyValid ? "Yes" : "No")
            });

            if ((d.MailtoRua?.Count ?? 0) > 0 || (d.HttpRua?.Count ?? 0) > 0)
            {
                var list = new List<string>();
                if (d.MailtoRua != null) list.AddRange(d.MailtoRua);
                if (d.HttpRua != null) list.AddRange(d.HttpRua);
                column.Section("RUA Destinations").BulletedList(list.ToArray());
            }

            if ((d.MailtoRuf?.Count ?? 0) > 0 || (d.HttpRuf?.Count ?? 0) > 0)
            {
                var list = new List<string>();
                if (d.MailtoRuf != null) list.AddRange(d.MailtoRuf);
                if (d.HttpRuf != null) list.AddRange(d.HttpRuf);
                column.Section("RUF Destinations").BulletedList(list.ToArray());
            }

            var deprecatedTags = d.DeprecatedTags;
            if (deprecatedTags != null && deprecatedTags.Count > 0)
            {
                column.Section("Deprecated Tags").BulletedList(deprecatedTags.ToArray());
            }

            var dmarcRecommendations = d.Recommendations;
            if (dmarcRecommendations != null && dmarcRecommendations.Count > 0)
            {
                column.Section("Recommendations").BulletedList(dmarcRecommendations.Select(r => r.Title ?? r.Code).ToArray());
            }

            var dmarcPositives = d.Positives;
            if (dmarcPositives != null && dmarcPositives.Count > 0)
            {
                column.Section("Positives").BulletedList(dmarcPositives.Select(p => p.Title ?? p.Code).ToArray());
            }

            var dmarcHighlights = d.Highlights;
            if (dmarcHighlights != null && dmarcHighlights.Count > 0)
            {
                column.Section("Highlights").BulletedList(dmarcHighlights);
            }
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildBimiBlock(DomainBucket bucket)
    {
        if (bucket.Bimi == null)
        {
            return null;
        }

        var bi = bucket.Bimi;
        return column =>
        {
            column.Section("BIMI").KeyValues(new (string, object?)[]
            {
                ("Record Present", bi.BimiRecordExists ? "Yes" : "No"),
                ("Starts Correctly", bi.StartsCorrectly ? "Yes" : "No"),
                ("Location", string.IsNullOrWhiteSpace(bi.Location) ? "-" : bi.Location),
                ("Authority", string.IsNullOrWhiteSpace(bi.Authority) ? "-" : bi.Authority),
                ("SVG Valid", bi.SvgValid ? "Yes" : (string.IsNullOrWhiteSpace(bi.SvgInvalidReason) ? "No" : $"No: {bi.SvgInvalidReason}")),
                ("VMC Present", bi.ValidVmc ? "Yes" : "No")
            });
        };
    }

    private static Action<SheetComposer.ColumnComposer>? BuildClassificationBlock(DomainBucket bucket)
    {
        if (bucket.Classification == null)
        {
            return null;
        }

        var classification = bucket.Classification;
        return column =>
        {
            column.Section("Classification").KeyValues(new (string, object?)[]
            {
                ("Category", classification.Classification),
                ("Confidence", classification.Confidence),
                ("Status", classification.Status)
            });

            if (classification.ScoreBreakdown != null && classification.ScoreBreakdown.Count > 0)
            {
                var list = classification.ScoreBreakdown.Select(kv => $"{kv.Key}: {kv.Value:0.##}").ToArray();
                column.Section("Score Breakdown").BulletedList(list);
            }
        };
    }

    private static void RenderProviderBlock(SheetComposer composer, SheetComposer.ColumnComposer column, DomainBucket bucket)
    {
        try
        {
            var chain = ProviderChainBuilder.Build(bucket.Mx, bucket.Spf);
            var summary = new List<(string, object?)>();

            if (!string.IsNullOrWhiteSpace(chain.Primary)) summary.Add(("Primary", chain.Primary));
            if ((chain.Gateways?.Count ?? 0) > 0) summary.Add(("Gateways", string.Join(", ", chain.Gateways!)));
            if (chain.Outbound.Count > 0) summary.Add(("Outbound", string.Join(", ", chain.Outbound)));

            try
            {
                var hints = ProviderHintsBuilder.Build(bucket.Mx, chain.Primary);
                if (hints.ConfidencePercent > 0) summary.Add(("Confidence", $"{hints.ConfidencePercent}%"));
                if (hints.SingleMxOk) summary.Add(("Single-MX OK", "Yes"));
                if (hints.MinDkimSelectorsToPass > 0) summary.Add(("Min DKIM Selectors", hints.MinDkimSelectorsToPass));
                if (hints.RecommendedMinMxRecords > 0) summary.Add(("Recommended Min MX", hints.RecommendedMinMxRecords));
            }
            catch { }

            var legend = "Legend: Confidence = detection certainty; Single‑MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform.";

            var topLinks = new List<(string Title, string Url)>();
            try
            {
                var links = bucket.Mx?.ProviderHelp ?? bucket.Spf?.ProviderHelp;
                var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase)) ?? links?.FirstOrDefault();
                var topics = primaryHelp?.Topics;
                if (topics != null && topics.Count > 0)
                {
                    topLinks = topics
                        .Where(t => !string.IsNullOrWhiteSpace(t?.Url))
                        .Take(3)
                        .Select(t =>
                        {
                            var fmt = LinkFormatter.Format(t!.Url ?? string.Empty);
                            var title = string.IsNullOrWhiteSpace(t.Title) ? (t.Topic ?? fmt.Title) : t.Title!;
                            return (title, fmt.Url);
                        })
                        .ToList();
                }
            }
            catch { }

            if (summary.Count == 0 && topLinks.Count == 0)
            {
                return;
            }

            column.Section("Providers");
            if (summary.Count > 0)
            {
                column.KeyValues(summary);
            }

            column.BulletedList(new[] { legend });

            if (topLinks.Count > 0)
            {
                column.Section("Top Links");
                var range = column.TableFrom(topLinks.Select(t => new { Title = t.Title, Url = t.Url }).ToList(), title: null, configure: o => o.HeaderCase = HeaderCase.Title, visuals: v => v.FreezeHeaderRow = true);
                try
                {
                    foreach (var row in composer.Sheet.RowsObjects(range))
                    {
                        var titleCell = row.CellByHeader("Title");
                        var urlCell = row.CellByHeader("Url");
                        string urlRef = IndexToCol(urlCell.ColumnIndex) + titleCell.RowIndex.ToString();
                        string safeTitle = (row.GetOrDefault<string>("Title", string.Empty) ?? string.Empty).Replace("\"", "\"\"");
                        row.SetFormula("Title", $"=HYPERLINK({urlRef},\"{safeTitle}\")");
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static Action<SheetComposer.ColumnComposer>? BuildTransportSummaryBlock(DomainBucket bucket)
    {
        if (bucket.Mtasts == null && bucket.TlsRpt == null)
        {
            return null;
        }

        return column =>
        {
            var details = new List<(string, object?)>();

            if (bucket.Mtasts != null)
            {
                var m = bucket.Mtasts;
                details.Add(("MTA-STS", m.Status ?? "-"));
                details.Add(("Mode", m.Mode ?? "-"));
                details.Add(("Max-Age", m.MaxAge));
                details.Add(("DNS Present", m.DnsRecordPresent ? "Yes" : "No"));
                details.Add(("DNS TTL (s)", m.DnsRecordTtl?.ToString() ?? "-"));
                details.Add(("CNAME Resolved", m.IsCnameResolved ? "Yes" : "No"));
                details.Add(("CNAME TTL (s)", m.CnameTtl?.ToString() ?? "-"));
                details.Add(("Policy Valid", m.PolicyValid ? "Yes" : "No"));
                details.Add(("Has MX", m.HasMx ? "Yes" : "No"));
                details.Add(("MX Aligned", m.MxAligned ? "Yes" : "No"));
            }

            if (bucket.TlsRpt != null)
            {
                var t = bucket.TlsRpt;
                details.Add(("TLS-RPT", t.Status ?? "-"));
                details.Add(("Record Exists", t.TlsRptRecordExists ? "Yes" : "No"));
                details.Add(("DNS TTL (s)", t.DnsRecordTtl?.ToString() ?? "-"));
                details.Add(("CNAME Resolved", t.IsCnameResolved ? "Yes" : "No"));
                details.Add(("CNAME TTL (s)", t.CnameTtl?.ToString() ?? "-"));
                details.Add(("Policy Valid", t.PolicyValid ? "Yes" : "No"));
                details.Add(("mailto RUA", t.MailtoRua?.Count ?? 0));
                details.Add(("http RUA", t.HttpRua?.Count ?? 0));
            }

            if (details.Count > 0)
            {
                column.Section("Transport Summary").KeyValues(details);
            }
        };
    }

}


