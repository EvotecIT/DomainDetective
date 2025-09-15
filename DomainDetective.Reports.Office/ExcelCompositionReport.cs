using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;
using System.IO;
#if NET8_0
using OfficeIMO.Excel;
using OfficeIMO.Excel.Fluent;
using DocumentFormat.OpenXml.Spreadsheet;
using SixLabors.ImageSharp;
#endif

namespace DomainDetective.Reports.Office;

/// <summary>
/// Excel composition across mixed view items (Index, Overview, per-domain sheets).
/// Implemented for net8.0 using OfficeIMO.Excel.
/// </summary>
public static partial class ExcelCompositionReport
{
    public static void Generate(
        string path,
        IReadOnlyList<object> items,
        ReportScope scope,
        OrderingOptions? ordering = null,
        ExcelProfile profile = ExcelProfile.Workbook)
    {
#if !NET8_0
        throw new NotSupportedException("Excel composition requires .NET 8.0");
#else
        if (items == null || items.Count == 0) throw new ArgumentException("No items to compose.", nameof(items));
        var compGroups = CompositionBuilder.GroupBySubject(items);
        var order = (ordering != null) ? ordering.DomainOrder : DomainOrder.Alphabetical;
        var orderedComp = CompositionBuilder.OrderDomains(items, compGroups, order);
        var domains = orderedComp.Select(kv => new KeyValuePair<string, DomainBucket>(kv.Key, Map(kv.Value))).ToList();

        using var doc = ExcelDocument.Create(path);
        doc.AsFluent().Info(i => i
            .Title("Domain Detective — Excel Composition")
            .Author("DomainDetective")
            .Company("Evotec")
            .Application("OfficeIMO.Excel")
            .Keywords("excel,report,domains")).End();

        BuildOverviewSheet(doc, items, order, domains);

        // Per-domain sheets (skip in Dashboard profile)
        if (profile != ExcelProfile.Dashboard)
        {
            var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in domains)
            {
                var name = MakeUniqueSheetName(kv.Key, usedNames); var b = kv.Value;
                var s = new SheetComposer(doc, name);
                s.Title($"Mail & DNS — {name}");
            s.SectionWithAnchor("Overview");
            s.DefinitionList(new (string, object?)[] {
                ("MX", b.Mx?.Status ?? "-"),
                ("SPF", b.Spf?.Status ?? "-"),
                ("DKIM", DomainDetective.Reports.DisplayFormatting.ComposeDkimSummary(b.Dkim, includeSelectorCount: true)),
                ("DMARC", b.Dmarc?.Status ?? "-"),
                ("MTA-STS", b.Mtasts?.Status ?? "-"),
                ("TLS-RPT", b.TlsRpt?.Status ?? "-"),
                ("DNSSEC", DomainDetective.Reports.DisplayFormatting.ComposeDnssecSummary(b.Dnssec)),
                ("RPKI", DomainDetective.Reports.DisplayFormatting.ComposeRpkiSummary(b.Rpki))
            }, columns: 3);

            // Providers (Primary · Gateways · Outbound) + quick top links
            try
            {
                var chain = ProviderChainBuilder.Build(b.Mx, b.Spf);
                var providerKvp = new List<(string, object?)>();
                if (!string.IsNullOrWhiteSpace(chain.Primary)) providerKvp.Add(("Primary", chain.Primary));
                if ((chain.Gateways?.Count ?? 0) > 0) providerKvp.Add(("Gateways", string.Join(", ", chain.Gateways!)));
                if (chain.Outbound.Count > 0) providerKvp.Add(("Outbound", string.Join(", ", chain.Outbound)));
                try {
                    var hints = ProviderHintsBuilder.Build(b.Mx, chain.Primary);
                    if (hints.ConfidencePercent > 0) providerKvp.Add(("Confidence", $"{hints.ConfidencePercent}%"));
                    if (hints.SingleMxOk) providerKvp.Add(("Single-MX OK", "Yes"));
                    if (hints.MinDkimSelectorsToPass > 0) providerKvp.Add(("Min DKIM Selectors", hints.MinDkimSelectorsToPass));
                    if (hints.RecommendedMinMxRecords > 0) providerKvp.Add(("Recommended Min MX", hints.RecommendedMinMxRecords));
                } catch { }
                if (providerKvp.Count > 0)
                {
                    s.SectionWithAnchor("Providers");
                    s.PropertiesGrid(providerKvp.ToArray(), columns: 3);
                    // Legend line for provider hints (parity with Word/HTML)
                    try { s.BulletedList(new [] { "Legend: Confidence = detection certainty; Single‑MX OK = vendor supports single MX; Gateway = inbound security gateway; Outbound = separate sender platform." }); } catch { }

                    // Top links (take 3 from primary provider help if available)
                    try
                    {
                        var links = b.Mx?.ProviderHelp ?? b.Spf?.ProviderHelp;
                        var primaryHelp = links?.FirstOrDefault(p => string.Equals(p?.ProviderName, chain.Primary, StringComparison.OrdinalIgnoreCase))
                                          ?? links?.FirstOrDefault();
                        if (primaryHelp != null && (primaryHelp.Topics?.Count ?? 0) > 0)
                        {
                            var top = primaryHelp.Topics.Where(t => !string.IsNullOrWhiteSpace(t?.Url)).Take(3).ToList();
                            if (top.Count > 0)
                            {
                                s.Section("Top Links");
                                var linkRows = top.Select(t => {
                                    var title = string.IsNullOrWhiteSpace(t?.Title) ? t!.Topic : t!.Title;
                                    var fmt = LinkFormatter.Format(t!.Url ?? string.Empty);
                                    return new { Title = string.IsNullOrWhiteSpace(title) ? fmt.Title : title!, Url = fmt.Url };
                                }).ToList();
                                var linksRange = s.TableFrom(linkRows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                                try
                                {
                                    // Convert Title to clickable HYPERLINK(Url, Title)
                                    foreach (var row in s.Sheet.RowsObjects(linksRange))
                                    {
                                        // Skip header row is not included in RowsObjects (it starts from second row already)
                                        var titleCell = row.CellByHeader("Title");
                                        var urlCell = row.CellByHeader("Url");
                                        string urlRef = IndexToCol(urlCell.ColumnIndex) + titleCell.RowIndex.ToString();
                                        var safeTitle = row.GetOrDefault<string>("Title", string.Empty) ?? string.Empty;
                                        safeTitle = safeTitle.Replace("\"", "\"\""); // Excel formula escaping: double the quotes
                                        row.SetFormula("Title", $"=HYPERLINK({urlRef},\"{safeTitle}\")");
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // Banded left-to-right layout: Email Auth | Transport | Infra/Reputation
            s.Columns(3, cols => {
                var auth = cols[0];
                var trans = cols[1];
                var infra = cols[2];

                // Column 1 — Email Authentication
                auth.Section("Email Authentication");

                // SPF (rich)
                if (b.Spf != null)
                {
                    var spf = b.Spf;
                    var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(spf);
                    var props = new System.Collections.Generic.List<(string, object?)> {
                        ("Status", spf.Status ?? "-"),
                        ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                        ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                        ("DNS Lookups", sec?.DnsLookupsCount ?? spf.DnsLookupsCount),
                    };
                    if (!string.IsNullOrWhiteSpace(spf.Raw?.AllMechanism)) props.Add(("All Mechanism", spf.Raw!.AllMechanism!));
                    auth.Section("SPF").KeyValues(props.ToArray());

                    if ((sec?.Findings.Count ?? 0) > 0)
                    {
                        var rows = sec!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                        var a1 = auth.TableFrom(rows, title: "Findings", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        s.ApplyColumnSizing(a1, opt => {
                            opt.ShortHeaders.Add("Severity");
                            opt.MediumHeaders.UnionWith(new [] { "Code", "Target" });
                            opt.LongHeaders.Add("Message");
                            opt.WrapHeaders.Add("Message");
                        });
                    }
                    if (!string.IsNullOrWhiteSpace(sec?.SpfRecord))
                    {
                        auth.Section("Evidence").KeyValues(new (string, object?)[] { ("SPF Record", sec!.SpfRecord) });
                    }
                    if ((sec?.Mechanisms.Count ?? 0) > 0)
                    {
                        var mech = sec!.Mechanisms.Select(m => new { Prefix = m.Qualifier, Type = m.Type, Value = m.Value, Provider = m.Provider }).ToList();
                        var mechRange = auth.TableFrom(mech, title: "Mechanisms", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        s.ApplyColumnSizing(mechRange, opt => {
                            opt.ShortHeaders.Add("Prefix");
                            opt.MediumHeaders.Add("Type");
                            opt.LongHeaders.Add("Value");
                            opt.WrapHeaders.Add("Value");
                        });
                    }
                    if ((sec?.FlattenedUniqueIpCount ?? 0) + (sec?.FlattenedDuplicateIpCount ?? 0) + (sec?.FlattenedTokenCount ?? 0) > 0)
                    {
                        auth.Section("Flattened IP Analysis").KeyValues(new (string, object?)[] {
                            ("Unique IPs", sec!.FlattenedUniqueIpCount),
                            ("Duplicate IPs", sec!.FlattenedDuplicateIpCount),
                            ("Tokens Resolved", sec!.FlattenedTokenCount),
                        });
                    }
                    if ((sec?.ProviderHelp.Count ?? 0) > 0)
                    {
                        var list = sec!.ProviderHelp.Take(8).Select(t => string.IsNullOrWhiteSpace(t.Title) ? (t.Url ?? string.Empty) : t.Title!).ToArray();
                        auth.Section("Provider Help").BulletedList(list);
                    }
                }

                // DKIM (selectors, TTL, findings, evidence)
                if (b.Dkim != null && b.Dkim.Count > 0)
                {
                    var dk = DomainDetective.Reports.SectionProjectors.BuildDkim(b.Dkim, b.Ttl);
                    auth.Section("DKIM").KeyValues(new (string, object?)[] {
                        ("Selectors", b.Dkim.Count),
                        ("Any Weak", b.Dkim.Any(x => x.WeakKey) ? "Yes" : "No")
                    });
                    if (dk != null && dk.Rows.Count > 0)
                    {
                        var rows = dk.Rows.Select(r => new {
                            Selector = r.Selector,
                            Status = string.IsNullOrWhiteSpace(r.Status) ? "-" : r.Status,
                            KeyBits = string.IsNullOrWhiteSpace(r.KeyBits) ? "-" : r.KeyBits,
                            Alg = string.IsNullOrWhiteSpace(r.Hash) ? "-" : r.Hash,
                            Weak = r.Weak ? "Yes" : "No",
                            Flags = string.IsNullOrWhiteSpace(r.Flags) ? string.Empty : r.Flags,
                            TTL = r.TtlSeconds.HasValue ? r.TtlSeconds.Value.ToString() : "-"
                        }).ToList();
                        var dkimSelRange = auth.TableFrom(rows, title: "Selectors", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        s.ApplyColumnSizing(dkimSelRange, opt => {
                            opt.ShortHeaders.UnionWith(new [] { "Status", "Weak", "Key Bits", "Alg", "TTL" });
                            opt.MediumHeaders.UnionWith(new [] { "Selector", "Flags" });
                        });
                    }
                    if (dk != null && dk.Findings.Count > 0)
                    {
                        var rows = dk.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                        var dkimFindRange = auth.TableFrom(rows, title: "Findings", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        s.ApplyColumnSizing(dkimFindRange, opt => {
                            opt.ShortHeaders.Add("Severity");
                            opt.MediumHeaders.UnionWith(new [] { "Code", "Target" });
                            opt.LongHeaders.Add("Message");
                            opt.WrapHeaders.Add("Message");
                        });
                    }
                    if (dk != null && dk.Rows.Any(r => !string.IsNullOrWhiteSpace(r.Record)))
                    {
                        var recRows = dk.Rows.Where(r => !string.IsNullOrWhiteSpace(r.Record))
                            .Select(r => new { r.Selector, Record = r.Record })
                            .ToList();
                        var dkimEvRange = auth.TableFrom(recRows, title: "Evidence", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        s.ApplyColumnSizing(dkimEvRange, opt => {
                            opt.MediumHeaders.Add("Selector");
                            opt.LongHeaders.Add("Record");
                            opt.WrapHeaders.Add("Record");
                        });
                    }
                }

                // DMARC
                if (b.Dmarc != null)
                {
                    var d = b.Dmarc;
                    auth.Section("DMARC").KeyValues(new (string, object?)[] {
                        ("Record Present", d.DmarcRecordExists ? "Yes" : "No"),
                        ("Starts Correctly", d.StartsCorrectly ? "Yes" : "No"),
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
                        auth.Section("RUA Destinations").BulletedList(list.ToArray());
                    }
                    if ((d.MailtoRuf?.Count ?? 0) > 0 || (d.HttpRuf?.Count ?? 0) > 0)
                    {
                        var list = new List<string>();
                        if (d.MailtoRuf != null) list.AddRange(d.MailtoRuf);
                        if (d.HttpRuf != null) list.AddRange(d.HttpRuf);
                        auth.Section("RUF Destinations").BulletedList(list.ToArray());
                    }
                    if ((d.DeprecatedTags?.Count ?? 0) > 0) { auth.Section("Deprecated Tags").BulletedList(d.DeprecatedTags.ToArray()); }
                    if ((d.Recommendations?.Count ?? 0) > 0) { auth.Section("Recommendations").BulletedList(d.Recommendations.Select(r => r.Title ?? r.Code).ToArray()); }
                    if ((d.Positives?.Count ?? 0) > 0) { auth.Section("Positives").BulletedList(d.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
                    if ((d.Highlights?.Count ?? 0) > 0) { auth.Section("Highlights").BulletedList(d.Highlights); }
                }

                // BIMI
                if (b.Bimi != null)
                {
                    var bi = b.Bimi;
                    auth.Section("BIMI").KeyValues(new (string, object?)[] {
                        ("Record Present", bi.BimiRecordExists ? "Yes" : "No"),
                        ("Starts Correctly", bi.StartsCorrectly ? "Yes" : "No"),
                        ("Location", string.IsNullOrWhiteSpace(bi.Location) ? "-" : bi.Location),
                        ("Authority", string.IsNullOrWhiteSpace(bi.Authority) ? "-" : bi.Authority),
                        ("SVG Valid", bi.SvgValid ? "Yes" : (string.IsNullOrWhiteSpace(bi.SvgInvalidReason) ? "No" : $"No: {bi.SvgInvalidReason}")),
                        ("VMC Present", bi.ValidVmc ? "Yes" : "No")
                    });
                }

                // Optional classification
                if (b.Classification != null)
                {
                    auth.Section("Classification").KeyValues(new (string, object?)[] {
                        ("Category", b.Classification.Classification),
                        ("Confidence", b.Classification.Confidence),
                        ("Status", b.Classification.Status)
                    });
                    if (b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
                    {
                        var rows = b.Classification.ScoreBreakdown.Select(kv2 => new { Name = kv2.Key, Value = kv2.Value }).ToList();
                        var list = rows.Select(r => $"{r.Name}: {r.Value:0.##}").ToArray();
                        auth.Section("Score Breakdown").BulletedList(list);
                    }
                }

                // Column 2 — Transport
                trans.Section("Transport");
                if (b.Mtasts != null || b.TlsRpt != null)
                {
                    var tp = new System.Collections.Generic.List<(string, object?)>();
                    if (b.Mtasts != null)
                    {
                        tp.Add(("MTA-STS", b.Mtasts.Status ?? "-"));
                        tp.Add(("Mode", b.Mtasts.Mode ?? "-"));
                        tp.Add(("Max-Age", b.Mtasts.MaxAge));
                        tp.Add(("DNS Present", b.Mtasts.DnsRecordPresent ? "Yes" : "No"));
                        tp.Add(("Policy Valid", b.Mtasts.PolicyValid ? "Yes" : "No"));
                        tp.Add(("MX Aligned", b.Mtasts.MxAligned ? "Yes" : "No"));
                    }
                    if (b.TlsRpt != null)
                    {
                        tp.Add(("TLS-RPT", b.TlsRpt.Status ?? "-"));
                        tp.Add(("Record Exists", b.TlsRpt.TlsRptRecordExists ? "Yes" : "No"));
                        tp.Add(("Policy Valid", b.TlsRpt.PolicyValid ? "Yes" : "No"));
                        tp.Add(("mailto RUA", (b.TlsRpt.MailtoRua?.Count ?? 0)));
                        tp.Add(("http RUA", (b.TlsRpt.HttpRua?.Count ?? 0)));
                    }
                    if (tp.Count > 0) trans.Section("Transport Summary").KeyValues(tp.ToArray());
                }
                if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
                {
                    trans.Section("MailTLS");
                    void RenderTls(string label, DomainDetective.Views.MailTlsInfo info)
                    {
                        if (info == null) return;
                        trans.Section(label);
                        if (info.Servers != null && info.Servers.Count > 0)
                        {
                            var rows = info.Servers.Select(v => new {
                                Server = v.Key,
                                Grade = v.Grade.ToString(),
                                CertValid = v.CertificateValid ? "Yes" : "No",
                                Chain = v.ChainValid ? "Yes" : "No",
                                DaysToExp = v.DaysToExpire,
                                Expired = v.IsExpired ? "Yes" : "No",
                                Proto = v.Protocol,
                                TLS13 = v.Tls13Used ? "Yes" : (v.SupportsTls13 ? "Supported" : "No"),
                                Cipher = v.CipherSuite,
                                Issuer = v.Issuer,
                                ValidTo = v.ValidTo?.ToString("yyyy-MM-dd") ?? ""
                            }).ToList();
                            var tlsRange = trans.TableFrom(rows, title: label + " Servers", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                                v.NumericColumnFormats["DaysToExp"] = "0"; v.FreezeHeaderRow = true;
                                v.TextBackgrounds["Grade"] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                                    { "A", "#D1E7DD" }, { "B", "#E2E3FF" }, { "C", "#FFF4CE" }, { "D", "#F8D7DA" }, { "F", "#F8D7DA" }
                                };
                            });
                            s.ApplyColumnSizing(tlsRange, opt => {
                                opt.MediumHeaders.UnionWith(new [] { "Server", "Proto", "Cipher", "Issuer" });
                                opt.ShortHeaders.UnionWith(new [] { "Grade", "CertValid", "Chain", "Hostname", "TLS13", "DaysToExp", "Expired", "ValidTo" });
                                opt.WrapHeaders.Add("Server");
                            });
                        }
                    }
                    if (b.SmtpTls != null) RenderTls("SMTP", b.SmtpTls);
                    if (b.ImapTls != null) RenderTls("IMAP", b.ImapTls);
                    if (b.PopTls != null) RenderTls("POP3", b.PopTls);
                }
                if (b.Mx != null)
                {
                    var mx = b.Mx;
                    trans.Section("MX").KeyValues(new (string, object?)[] {
                        ("Record Present", mx.MxRecordExists ? "Yes" : "No"),
                        ("IPv6 Supported", mx.Ipv6Supported ? "Yes" : "No"),
                        ("Has Backup Servers", mx.HasBackupServers ? "Yes" : "No"),
                        ("Null MX", mx.HasNullMx ? "Yes" : "No"),
                        ("Priorities In Order", mx.PrioritiesInOrder ? "Yes" : "No"),
                        ("Points to CNAME", mx.PointsToCname ? "Yes" : "No"),
                        ("Points to IP", mx.PointsToIpAddress ? "Yes" : "No"),
                        ("Target Consistent Across NS", mx.TargetAddressConsistentAcrossNs ? "Yes" : "No")
                    });
                    if ((mx.MxRecords?.Count ?? 0) > 0)
                    {
                        var mxRows = mx.MxRecords.Select(r => new { Host = r }).ToList();
                        trans.TableFrom(mxRows, title: "MX Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
                    }
                    if ((mx.Recommendations?.Count ?? 0) > 0) { trans.Section("Recommendations").BulletedList(mx.Recommendations.Select(r => r.Title ?? r.Code).ToArray()); }
                    if ((mx.Positives?.Count ?? 0) > 0) { trans.Section("Positives").BulletedList(mx.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
                }
                if (b.Arc != null)
                {
                    var arc = b.Arc;
                    trans.Section("ARC").KeyValues(new (string, object?)[] {
                        ("ARC Headers Present", arc.ArcHeadersFound ? "Yes" : "No"),
                        ("Seal Count", arc.SealCount),
                        ("AAR Count", arc.AarCount),
                        ("Valid Chain", arc.ValidChain ? "Yes" : "No"),
                        ("Chain State", arc.ChainState)
                    });
                    if ((arc.Highlights?.Count ?? 0) > 0) { trans.Section("Highlights").BulletedList(arc.Highlights); }
                    if ((arc.Recommendations?.Count ?? 0) > 0) { trans.Section("Recommendations").BulletedList(arc.Recommendations.Select(r => r.Title ?? r.Code).ToArray()); }
                }

                // Column 3 — Infrastructure & Reputation
                infra.Section("Infrastructure & Reputation");
                if (b.Dnssec != null || b.Dane != null)
                {
                    var rows = new List<(string, object?)>();
                    if (b.Dnssec != null) rows.Add(("DNSSEC", b.Dnssec.Status ?? "-"));
                    if (b.Dane != null) rows.Add(("DANE", b.Dane.Status ?? "-"));
                    if (rows.Count > 0) infra.Section("DNSSEC/DANE").KeyValues(rows.ToArray());
                }
                if (b.Dnsbl != null)
                {
                    var db = b.Dnsbl;
                    infra.Section("DNSBL").KeyValues(new (string, object?)[] {
                        ("Providers Checked", db.ProvidersChecked),
                        ("Hosts Checked", db.HostsChecked),
                        ("Hosts Listed", db.HostsListed)
                    });
                    if (db.HostSummaries != null && db.HostSummaries.Count > 0)
                    {
                        var hostRows = db.HostSummaries.Select(h => new { Host = h.Key, Listed = h.Listed, Total = h.Total, Blacklists = string.Join(", ", h.Blacklists ?? new List<string>()) }).ToList();
                        var dnsblRange = infra.TableFrom(hostRows, title: "Host Summaries", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                            v.NumericColumnFormats["Listed"] = "0"; v.NumericColumnFormats["Total"] = "0"; v.FreezeHeaderRow = true;
                        });
                        s.ApplyColumnSizing(dnsblRange, opt => {
                            opt.MediumHeaders.Add("Host");
                            opt.NumericHeaders.UnionWith(new [] { "Listed", "Total" });
                            opt.LongHeaders.Add("Blacklists");
                            opt.WrapHeaders.Add("Blacklists");
                        });
                    }
                }
                if (b.Ns != null)
                {
                    var ns = b.Ns;
                    infra.Section("NS").KeyValues(new (string, object?)[] {
                        ("Record Present", ns.NsRecordExists ? "Yes" : "No"),
                        ("At Least Two", ns.AtLeastTwoRecords ? "Yes" : "No"),
                        ("All Have A/AAAA", ns.AllHaveAOrAaaa ? "Yes" : "No"),
                        ("Glue Complete", ns.GlueRecordsComplete ? "Yes" : "No"),
                        ("Glue Consistent", ns.GlueRecordsConsistent ? "Yes" : "No"),
                        ("Delegation Matches", ns.DelegationMatches ? "Yes" : "No"),
                        ("Distinct ASNs", ns.AsnDistinctCount)
                    });
                    if ((ns.NsRecords?.Count ?? 0) > 0)
                    {
                        infra.TableFrom(ns.NsRecords.Select(x => new { NS = x }).ToList(), title: "NS Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                    }
                    if ((ns.ParentNsRecords?.Count ?? 0) > 0)
                    {
                        infra.TableFrom(ns.ParentNsRecords.Select(x => new { ParentNS = x }).ToList(), title: "Parent NS Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                    }
                }
                if (b.Soa != null)
                {
                    var soa = b.Soa;
                    infra.Section("SOA").KeyValues(new (string, object?)[] {
                        ("Primary NS", soa.PrimaryNameServer),
                        ("Responsible", soa.ResponsibleMailbox),
                        ("Serial", soa.SerialNumber),
                        ("Serial Format", soa.SerialFormatValid ? "Valid" : "Check"),
                        ("Refresh", soa.Refresh), ("Retry", soa.Retry), ("Expire", soa.Expire),
                        ("Minimum", soa.Minimum), ("Neg Cache TTL", soa.NegativeCacheTtl)
                    });
                }
                if (b.Caa != null)
                {
                    var caa = b.Caa;
                    infra.Section("CAA").KeyValues(new (string, object?)[] {
                        ("Valid Records", caa.ValidRecords),
                        ("Invalid Records", caa.InvalidRecords),
                        ("Conflicting", caa.Conflicting ? "Yes" : "No"),
                        ("Duplicate Issuers", caa.HasDuplicateIssuers ? "Yes" : "No")
                    });
                    if ((caa.CanIssueCertificatesForDomain?.Count ?? 0) > 0) { infra.Section("Allowed CAs").BulletedList(caa.CanIssueCertificatesForDomain.ToArray()); }
                    if ((caa.CanIssueWildcardCertificatesForDomain?.Count ?? 0) > 0) { infra.Section("Allowed Wildcard CAs").BulletedList(caa.CanIssueWildcardCertificatesForDomain.ToArray()); }
                    if ((caa.CanIssueMail?.Count ?? 0) > 0) { infra.Section("Mail CAA Values").BulletedList(caa.CanIssueMail.ToArray()); }
                    if ((caa.ReportViolationEmail?.Count ?? 0) > 0) { infra.Section("Report-To Emails").BulletedList(caa.ReportViolationEmail.ToArray()); }
                }
                if (b.Rpki != null)
                {
                    var rp = b.Rpki;
                    infra.Section("RPKI").KeyValues(new (string, object?)[] {
                        ("Total Checked", rp.TotalChecked), ("Valid", rp.ValidCount), ("All Valid", rp.AllValid ? "Yes" : "No")
                    });
                    if ((rp.Results?.Count ?? 0) > 0)
                    {
                        var rpRows = rp.Results.Select(r => new { r.IpAddress, r.Prefix, r.Asn, Valid = r.Valid ? "Yes" : "No" }).ToList();
                        infra.TableFrom(rpRows, title: "RPKI Results", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Asn"] = "0"; v.FreezeHeaderRow = true; });
                    }
                }
                if (b.ZoneTransfer != null)
                {
                    var zt = b.ZoneTransfer;
                    infra.Section("Zone Transfer").KeyValues(new (string, object?)[] { ("Open", $"{zt.OpenCount}/{zt.TotalChecked}") });
                    if ((zt.ServerResults?.Count ?? 0) > 0)
                    {
                        var zRows = zt.ServerResults.Select(kv2 => new { Server = kv2.Key, Open = kv2.Value ? "Yes" : "No" }).ToList();
                        infra.TableFrom(zRows, title: "Servers", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                    }
                }
                if (b.Wildcard != null)
                {
                    var wc = b.Wildcard;
                    infra.Section("Wildcard DNS").KeyValues(new (string, object?)[] { ("Catch-All", wc.CatchAll ? "Yes" : "No") });
                    if ((wc.TestedNames?.Count ?? 0) > 0) { infra.Section("Tested Names").BulletedList(wc.TestedNames.ToArray()); }
                    if ((wc.ResolvedNames?.Count ?? 0) > 0) { infra.Section("Resolved Names").BulletedList(wc.ResolvedNames.ToArray()); }
                }
            }, columnWidth: 12, gutter: 2);
            // Re-enable AutoFit for cleaner per-domain sheets.
            s.Finish(autoFitColumns: true);
        }

        // (duplicate DKIM/DMARC detail blocks removed — handled earlier within the per-domain sheet scope)

        // (no extra per-domain sheets created; all deep tables appended to their domain sheet)

        // Summary sheet (counts by control)
        try
        {
            var sum = new SheetComposer(doc, "Summary");
            sum.Title("Control Summary");
            var controls = new[]{"MX","SPF","DKIM","DMARC","MTA-STS","TLS-RPT"};
            var rows = new List<object>();
            foreach (var c in controls)
            {
                int ok=0, warn=0, err=0, unk=0;
                foreach (var kv in domains)
                {
                    string status = c switch {
                        "MX" => kv.Value.Mx?.Status,
                        "SPF" => kv.Value.Spf?.Status,
                        "DKIM" => (kv.Value.Dkim.Count>0 ? (kv.Value.Dkim.Max(x=>x.Status) ?? "-") : "-"),
                        "DMARC" => kv.Value.Dmarc?.Status,
                        "MTA-STS" => kv.Value.Mtasts?.Status,
                        _ => kv.Value.TlsRpt?.Status
                    } ?? "-";
                    var s = status.Trim().ToLowerInvariant();
                    if (s.Contains("error") || s.Contains("fail")) err++;
                    else if (s.Contains("warn")) warn++;
                    else if (s=="-" || s.Contains("none") || s.Contains("missing")) unk++;
                    else ok++;
                }
                rows.Add(new { Control = c, OK = ok, Warning = warn, Error = err, Unknown = unk });
            }
            sum.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                v.NumericColumnFormats["OK"] = "0"; v.NumericColumnFormats["Warning"] = "0"; v.NumericColumnFormats["Error"] = "0"; v.NumericColumnFormats["Unknown"] = "0"; v.FreezeHeaderRow = true;
            });
            sum.Finish(autoFitColumns: true);
        }
        catch { }

        // Status Matrix sheet (Domain x Control)
        try
        {
            var mx = new SheetComposer(doc, "Matrix");
            mx.Title("Status Matrix");
            var matrix = new List<object>();
            foreach (var kv in domains)
            {
                var b = kv.Value; string dom = kv.Key;
                string dkim = b.Dkim.Count>0 ? (b.Dkim.Max(x=>x.Status) ?? "-") : "-";
                matrix.Add(new {
                    Domain = dom,
                    MX = b.Mx?.Status ?? "-",
                    SPF = b.Spf?.Status ?? "-",
                    DKIM = dkim,
                    DMARC = b.Dmarc?.Status ?? "-",
                    MTASTS = b.Mtasts?.Status ?? "-",
                    TLSRPT = b.TlsRpt?.Status ?? "-",
                    DNSBL = b.Dnsbl?.Status ?? "-",
                    NS = b.Ns?.Status ?? "-",
                    SOA = b.Soa?.Status ?? "-",
                    CAA = b.Caa?.Status ?? "-",
                    RPKI = b.Rpki?.Status ?? "-"
                });
            }
            mx.TableFrom(matrix, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                var ok = "#D1E7DD"; var warn = "#FFF4CE"; var err = "#F8D7DA"; var none = "#E9ECEF";
                foreach (var col in new[]{"MX","SPF","DKIM","DMARC","MTASTS","TLSRPT","DNSBL","NS","SOA","CAA","RPKI"})
                {
                    v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string,string>(System.StringComparer.OrdinalIgnoreCase) {
                        {"OK", ok},{"Pass", ok},{"Valid", ok},{"Warning", warn},{"Warn", warn},{"Error", err},{"Fail", err},{"-", none},{"None", none},{"Missing", none}
                    };
                }
                v.FreezeHeaderRow = true;
            });
            mx.Finish(autoFitColumns: true);
        }
        catch { }

        // SPF Providers summary sheet
        try
        {
            var sp = new SheetComposer(doc, "SPF Providers");
            sp.Title("SPF Providers");
            var agg = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in domains)
            {
                var pc = kv.Value.Spf?.ProviderCounts;
                if (pc == null) continue;
                foreach (var p in pc) agg[p.Key] = (agg.TryGetValue(p.Key, out var c) ? c : 0) + p.Value;
            }
            var rows = agg.OrderByDescending(kv2 => kv2.Value).Select(kv2 => new { Provider = kv2.Key, Tokens = kv2.Value }).ToList();
            sp.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Tokens"] = "0"; v.FreezeHeaderRow = true; });
            sp.Finish(autoFitColumns: true);
        }
        catch { }

        // All Recommendations sheet
        try
        {
            var recSheet = new SheetComposer(doc, "Recommendations");
            recSheet.Title("All Recommendations");
            var recRows = new List<object>();
            foreach (var kv in domains)
            {
                string d = kv.Key; var b = kv.Value;
                void AddRecs(string section, IEnumerable<DomainDetective.RecommendationAdvice>? list)
                {
                    if (list == null) return;
                    foreach (var r in list) recRows.Add(new { Domain = d, Section = section, Title = r.Title ?? r.Code });
                }
                AddRecs("MX", b.Mx?.Recommendations);
                AddRecs("SPF", b.Spf?.Recommendations);
                if (b.Dkim.Count>0) AddRecs("DKIM", b.Dkim.SelectMany(x => x.Recommendations ?? new List<DomainDetective.RecommendationAdvice>()));
                AddRecs("DMARC", b.Dmarc?.Recommendations);
                AddRecs("MTA-STS", b.Mtasts?.Recommendations);
                AddRecs("TLS-RPT", b.TlsRpt?.Recommendations);
                AddRecs("DNSBL", b.Dnsbl?.Recommendations);
                AddRecs("NS", b.Ns?.Recommendations);
                AddRecs("SOA", b.Soa?.Recommendations);
                AddRecs("CAA", b.Caa?.Recommendations);
                AddRecs("RPKI", b.Rpki?.Recommendations);
                AddRecs("ZoneTransfer", b.ZoneTransfer?.Recommendations);
                AddRecs("Wildcard", b.Wildcard?.Recommendations);
            }
            if (recRows.Count == 0) recRows.Add(new { Domain = "—", Section = "—", Title = "No recommendations" });
            var recRange = recSheet.TableFrom(recRows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
            recSheet.ApplyColumnSizing(recRange, opt => {
                opt.MediumHeaders.Add("Domain");
                opt.ShortHeaders.Add("Section");
                opt.LongHeaders.Add("Title");
                opt.WrapHeaders.Add("Title");
            });
            recSheet.Finish(autoFitColumns: true);
        }
        catch { }

        // References sheet (Word parity)
        try
        {
            var comp = CompositionBuilder.GroupBySubject(items);
            var refs = ReferencesCollector.CollectAll(comp.Values);
            var refSheet = new SheetComposer(doc, "References");
            refSheet.Title("All References");
            if (refs.Count == 0) { refSheet.BulletedList(new[] { "No references" }); }
            else
            {
                var rows = refs.Select(u => {
                    var f = LinkFormatter.Format(u);
                    return new { Title = f.Title, Url = f.Url };
                }).ToList();
                var refRange = refSheet.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                try
                {
                    foreach (var row in refSheet.Sheet.RowsObjects(refRange))
                    {
                        var titleCell = row.CellByHeader("Title");
                        var urlCell = row.CellByHeader("Url");
                        string urlRef = IndexToCol(urlCell.ColumnIndex) + titleCell.RowIndex.ToString();
                        string safeTitle = (row.GetOrDefault<string>("Title", string.Empty) ?? string.Empty).Replace("\"", "\"\"");
                        row.SetFormula("Title", $"=HYPERLINK({urlRef},\"{safeTitle}\")");
                    }
                }
                catch { }
                // Clamp widths for readable references
                refSheet.ApplyColumnSizing(refRange, opt => {
                    opt.LongHeaders.Add("Url");
                    opt.MediumHeaders.Add("Title");
                    // Do not wrap URLs; titles are hyperlinks already
                });
            }
            // Disable AutoFit here — URLs can be long and blow out column widths.
            refSheet.Finish(autoFitColumns: false);
        }
        catch { }

        } // end if (profile != ExcelProfile.Dashboard)

        // Index
        SheetIndex.Add(doc, sheetName: "Index", placeFirst: true, includeNamedRanges: false);
        SheetIndex.AddBackLinks(doc, tocSheetName: "Index", row: 2, col: 1, text: "← Index");

        doc.Save();
#if NET8_0
        try
        {
            var errs = doc.ValidateDocument();
            if (errs.Count > 0)
            {
                var report = string.Join(Environment.NewLine, errs.Select(e => $"{e.ErrorType}: {e.Description} at {e.Path?.XPath}"));
                File.WriteAllText(Path.ChangeExtension(path, ".xlsx.validation.txt"), report);
            }
        }
        catch { }
#endif
#endif
    }

}
