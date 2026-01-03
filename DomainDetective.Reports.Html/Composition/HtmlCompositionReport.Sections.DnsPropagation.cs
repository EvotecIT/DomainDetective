using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using DomainDetective.Reports;
using HtmlForgeX;
using HtmlForgeX.Containers.Tabler;

namespace DomainDetective.Reports.Html;

public static partial class HtmlCompositionReport
{
    private static void RenderDnsPropagationSection(TablerAccordion acc, DomainBucket b)
    {
        var items = b.DnsPropagation;
        if (items == null || items.Count == 0)
        {
            return;
        }

        var ordered = items
            .Where(i => i != null)
            .OrderBy(i => i.RecordType.ToString(), StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Subject, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var warn = ordered.Sum(i => i.WarningCount);
        var err = ordered.Sum(i => i.ErrorCount);
        var status = err > 0 ? "Error" : (warn > 0 ? "Warning" : "OK");

        acc.AddItem("DNS Propagation", item =>
        {
            item.Icon(TablerIconType.World);
            item.HeaderRight(c =>
            {
                c.Badge(err > 0 ? $"{err} Error" + (err > 1 ? "s" : "") : "0 Error", TablerBadgeColor.Danger, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(warn > 0 ? $"{warn} Warning" + (warn > 1 ? "s" : "") : "0 Warning", TablerBadgeColor.Warning, TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
                c.Badge(status, ColorForStatus(status), TablerBadgeVisualStyle.Light, TablerBadgeSize.Small, pill: true);
            });
            item.Content(content =>
            {
                content.Row(r => r.Column(TablerColumnNumber.Twelve, c2 =>
                {
                    RenderExecutionSnapshotCard(c2, g =>
                    {
                        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        AddGridPanelUnique(g, seen, "Status", status, PanelColorForStatus(status), light: true);
                        AddGridPanelUnique(g, seen, "Warnings", warn.ToString(), warn > 0 ? TablerColor.Orange : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "Errors", err.ToString(), err > 0 ? TablerColor.Red : TablerColor.Green, light: true);
                        AddGridPanelUnique(g, seen, "Tests", ordered.Count.ToString(), TablerColor.Blue, light: true);
                        try
                        {
                            var types = ordered.Select(x => x.RecordType.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                            AddGridPanelUnique(g, seen, "Record Types", types.Count > 0 ? string.Join(", ", types.Take(6)) + (types.Count > 6 ? $" (+{types.Count - 6})" : string.Empty) : "-", TablerColor.Azure, light: true);
                        }
                        catch { }
                    }, subtitle: "Multi-resolver DNS propagation visibility (by record type).");

                    RenderResultsTabsCard(c2, tabs =>
                    {
                        foreach (var dp in ordered)
                        {
                            var recordLabel = dp.RecordType.ToString();
                            var sec = SectionProjectors.BuildDnsPropagation(dp);

                            var tab = tabs.AddTab(recordLabel, panel =>
                            {
                                panel.Row(rr =>
                                {
                                    rr.Column(TablerColumnNumber.Twelve, col =>
                                    {
                                        if (sec == null)
                                        {
                                            col.Text("DNS propagation section could not be projected.").Style(TablerTextStyle.Muted);
                                            return;
                                        }

                                        if (dp.ResultsCapped)
                                        {
                                            col.Alert("Results capped", "This section is showing a bounded subset of resolver results to keep reports responsive.", TablerColor.Orange)
                                                .Icon(TablerIconType.InfoCircle);
                                        }

                                        col.Row(r2 =>
                                        {
                                            r2.Column(TablerColumnNumber.Six, left =>
                                            {
                                                RenderSummaryGrid(left, sec.Summary);
                                            });

                                            r2.Column(TablerColumnNumber.Six, right =>
                                            {
                                                RenderDnsPropagationMap(right, sec);
                                            });
                                        });

                                        col.Row(r2 =>
                                        {
                                            r2.Column(TablerColumnNumber.Twelve, col2 =>
                                            {
                                                RenderSignalsSummary(col2, sec.Findings.Select(f => f.Message), sec.Positives);
                                            });
                                        });

                                        if (sec.AnswerSets.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Answer sets").Icon(TablerIconType.Stack));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.AnswerSets.Select(a => new
                                                    {
                                                        AnswerSet = a.AnswerSetKey,
                                                        a.Servers,
                                                        a.Countries,
                                                        a.Locations,
                                                        SampleServers = a.SampleServers
                                                    }).ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }

                                        if (sec.Countries.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Country rollup").Icon(TablerIconType.Map2));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.Countries.Select(cn => new
                                                    {
                                                        cn.Country,
                                                        cn.Servers,
                                                        cn.Success,
                                                        cn.Errors,
                                                        cn.Majority,
                                                        cn.NonMajority
                                                    }).ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(10, new[] { 10, 25, 50 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }

                                        if (sec.Servers.Count > 0)
                                        {
                                            col.Card(card =>
                                            {
                                                card.Header(h => h.Title("Resolvers").Icon(TablerIconType.Server2));
                                                card.Body(body =>
                                                {
                                                    var rows = sec.Servers.Select(sv => new
                                                    {
                                                        sv.ServerIp,
                                                        sv.Country,
                                                        sv.Location,
                                                        sv.Asn,
                                                        sv.Success,
                                                        RTTms = sv.DurationMs,
                                                        Majority = sv.IsMajority,
                                                        sv.AnswerSetKey,
                                                        sv.Answers,
                                                        sv.Error
                                                    }).ToList();

                                                    var t = (DataTablesTable)body.Table(rows, TableType.DataTables);
                                                    ConfigureStandardDataTable(t);
                                                    t.EnablePaging(25, new[] { 10, 25, 50, 100 })
                                                        .EnableSearching()
                                                        .EnableOrdering();
                                                });
                                            });
                                        }

                                        RenderFindings(col, sec.Findings);

                                        RenderReferences(col, sec.References);
                                    });
                                });
                            }).WithIcon(TablerIconType.World);

                            var findings = dp.WarningCount + dp.ErrorCount;
                            if (findings > 0)
                            {
                                var badgeColor = dp.ErrorCount > 0 ? TablerBadgeColor.Danger : TablerBadgeColor.Warning;
                                tab.WithBadge(findings.ToString(), badgeColor);
                            }
                        }
                    });
                }));
            });
        });
    }

    private static void RenderDnsPropagationMap(TablerColumn col, SectionProjectors.DnsPropagationSection sec)
    {
        if (sec == null)
        {
            col.Text("No map data.").Style(TablerTextStyle.Muted);
            return;
        }

        var (levels, caption, baseColor) = BuildDnsPropagationRegionLevels(sec);
        if (levels.Count == 0)
        {
            col.Card(card =>
            {
                card.Header(h => h.Title("World map").Icon(TablerIconType.Map));
                card.Body(b =>
                {
                    b.Text("No mappable country data was found for this run.").Style(TablerTextStyle.Muted);
                });
            });
            return;
        }

        col.Card(card =>
        {
            card.Header(h => h.Title("World map").Icon(TablerIconType.Map));
            card.Body(body =>
            {
                body.VectorMap(vm =>
                {
                    vm.UseMap(JsVectorMapName.WorldMerc)
                        .Settings(s =>
                        {
                            s.Height("380px");
                            s.ZoomButtons(false);
                            s.ZoomOnScroll(false);
                        })
                        .ColorRegions(levels, baseColor: baseColor, minAlpha: 0.15, maxAlpha: 0.95);
                });
                body.Text(caption).Style(TablerTextStyle.Muted);
            });
        });
    }

    private static (Dictionary<string, int> levels, string caption, TablerColor baseColor) BuildDnsPropagationRegionLevels(SectionProjectors.DnsPropagationSection sec)
    {
        var issues = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var coverage = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var row in sec.Countries ?? new List<SectionProjectors.DnsPropagationSection.CountryRow>())
        {
            if (row == null) continue;
            if (!TryGetIso2Code(row.Country, out var iso2)) continue;
            if (!coverage.ContainsKey(iso2)) coverage[iso2] = 0;
            coverage[iso2] += Math.Max(0, row.Servers);

            var countIssues = Math.Max(0, row.Errors) + Math.Max(0, row.NonMajority);
            if (countIssues <= 0) continue;
            if (!issues.ContainsKey(iso2)) issues[iso2] = 0;
            issues[iso2] += countIssues;
        }

        if (issues.Count > 0)
        {
            return (ScaleToLevels(issues), "Darker red indicates more issues (errors + non‑majority answers).", TablerColor.Red);
        }

        return (ScaleToLevels(coverage), "Darker blue indicates more resolver coverage (servers queried).", TablerColor.Blue);
    }

    private static Dictionary<string, int> ScaleToLevels(Dictionary<string, int> values)
    {
        var levels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (values == null || values.Count == 0) return levels;

        var max = values.Values.DefaultIfEmpty(0).Max();
        if (max <= 0) return levels;

        foreach (var kv in values)
        {
            var v = kv.Value;
            if (v <= 0) continue;
            var lvl = (int)Math.Ceiling(v * 10d / max);
            if (lvl < 1) lvl = 1;
            if (lvl > 10) lvl = 10;
            levels[kv.Key] = lvl;
        }

        return levels;
    }

	    private static bool TryGetIso2Code(string? countryName, out string iso2)
	    {
	        iso2 = string.Empty;
	        if (countryName == null)
	        {
	            return false;
	        }
	        var raw = countryName.Trim();
	        if (raw.Length == 0)
	        {
	            return false;
	        }
	        if (raw.Length == 2 && raw.All(ch => char.IsLetter(ch)))
	        {
	            iso2 = raw.ToUpperInvariant();
	            return true;
	        }

        // Known official/legacy names used by resolver datasets.
        if (TryGetIso2FromOverrides(raw, out iso2))
        {
            return true;
        }

        // Comma-qualified ISO names: often resolve to the prefix country name, but a few need explicit mapping.
        if (raw.Contains(",", StringComparison.Ordinal))
        {
            if (TryGetIso2FromCommaQualified(raw, out iso2))
            {
                return true;
            }

            var first = raw.Split(',')[0].Trim();
            if (!string.IsNullOrWhiteSpace(first) && TryGetIso2Code(first, out iso2))
            {
                return true;
            }
        }

        // Best-effort enum mapping: sanitize to PascalCase identifier used by HtmlForgeX.Country.
        var normalized = StripDiacritics(raw);
        var id = ToEnumIdentifier(normalized);
        if (Enum.TryParse<Country>(id, ignoreCase: true, out var c))
        {
            iso2 = c.ToIso2().ToUpperInvariant();
            return true;
        }

        // Fallback: try to simplify known suffix patterns.
        if (normalized.EndsWith(" Darussalam", StringComparison.OrdinalIgnoreCase))
        {
            var firstWord = normalized.Split(' ')[0].Trim();
            if (TryGetIso2Code(firstWord, out iso2)) return true;
        }

        return false;
    }

    private static bool TryGetIso2FromOverrides(string name, out string iso2)
    {
        iso2 = string.Empty;
        if (string.IsNullOrWhiteSpace(name)) return false;

        var n = name.Trim();
        if (n.Equals("Czech Republic", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Czechia.ToIso2(); return true; }
        if (n.Equals("Russian Federation", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Russia.ToIso2(); return true; }
        if (n.Equals("Syrian Arab Republic", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Syria.ToIso2(); return true; }
        if (n.Equals("Swaziland", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Eswatini.ToIso2(); return true; }
        if (n.Equals("Viet Nam", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Vietnam.ToIso2(); return true; }
        if (n.Equals("Lao People's Democratic Republic", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Laos.ToIso2(); return true; }
        if (n.Equals("Côte d'Ivoire", StringComparison.OrdinalIgnoreCase) || n.Equals("Cote d'Ivoire", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.CotedIvoire.ToIso2(); return true; }
        if (n.Equals("Réunion", StringComparison.OrdinalIgnoreCase) || n.Equals("Reunion", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.Reunion.ToIso2(); return true; }
        if (n.Equals("Åland Islands", StringComparison.OrdinalIgnoreCase) || n.Equals("Aland Islands", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.AlandIslands.ToIso2(); return true; }
        return false;
    }

    private static bool TryGetIso2FromCommaQualified(string name, out string iso2)
    {
        iso2 = string.Empty;
        var n = name.Trim();
        if (n.Equals("Korea, Republic of", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.SouthKorea.ToIso2(); return true; }
        if (n.Equals("Macedonia, Republic of", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.NorthMacedonia.ToIso2(); return true; }
        if (n.Equals("Palestine, State of", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.PalestinianTerritories.ToIso2(); return true; }
        if (n.Equals("Bonaire, Sint Eustatius and Saba", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.CaribbeanNetherlands.ToIso2(); return true; }
        if (n.Equals("Virgin Islands, U.S.", StringComparison.OrdinalIgnoreCase) || n.Equals("Virgin Islands, U.S", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.USVirginIslands.ToIso2(); return true; }
        if (n.Equals("Congo, The Democratic Republic of the", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.CongoKinshasa.ToIso2(); return true; }
        if (n.Equals("Congo", StringComparison.OrdinalIgnoreCase)) { iso2 = Country.CongoBrazzaville.ToIso2(); return true; }
        return false;
    }

    private static string StripDiacritics(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var normalized = input.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            var cat = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (cat != UnicodeCategory.NonSpacingMark)
            {
                sb.Append(ch);
            }
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    private static string ToEnumIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var sb = new StringBuilder();
        var nextUpper = true;
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch))
            {
                sb.Append(nextUpper ? char.ToUpperInvariant(ch) : ch);
                nextUpper = false;
            }
            else
            {
                nextUpper = true;
            }
        }
        if (sb.Length == 0 || char.IsDigit(sb[0]))
        {
            sb.Insert(0, '_');
        }
        return sb.ToString();
    }
}
