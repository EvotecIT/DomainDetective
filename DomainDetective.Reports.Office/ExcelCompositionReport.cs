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
public static class ExcelCompositionReport
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

        // Overview sheet
        var overview = new SheetComposer(doc, "Overview");
        overview.Title("Security Overview", $"Generated {DateTime.Now:yyyy-MM-dd HH:mm}");

        // Build summary rows once via the shared builder
        var execRows = ExecutiveSummaryBuilder.Build(items, order);
        int totalWarn = execRows.Sum(r => r.Warnings);
        int totalErr = execRows.Sum(r => r.Errors);
        var sumRows = new List<object>(execRows.Count + 1);
        foreach (var r in execRows)
        {
            sumRows.Add(new {
                Domain = r.Domain,
                MX = r.Mx,
                SPF = r.Spf,
                DKIM = r.Dkim,
                DMARC = r.Dmarc,
                MTASTS = r.Mtasts,
                TLSRPT = r.TlsRpt,
                DNSSEC = r.Dnssec,
                RPKI = r.Rpki,
                Warnings = r.Warnings,
                Errors = r.Errors
            });
        }
        // Totals row at the end of the overview table
        sumRows.Add(new {
            Domain = "TOTAL",
            MX = string.Empty,
            SPF = string.Empty,
            DKIM = string.Empty,
            DMARC = string.Empty,
            MTASTS = string.Empty,
            TLSRPT = string.Empty,
            DNSSEC = string.Empty,
            RPKI = string.Empty,
            Warnings = totalWarn,
            Errors = totalErr
        });

        // KPI row
        overview.KpiRow(new (string, object?)[] {
            ("Domains", domains.Count),
            ("Warnings", totalWarn),
            ("Errors", totalErr)
        }, perRow: 3);

        // Identical wording to Word/Markdown/HTML via shared helper
        try
        {
            var overviewLine = OverviewWording.ComposeFromItems(items);
            overview.Section("Overview");
            overview.PropertiesGrid(new (string, object?)[] { ("Summary", overviewLine) }, columns: 1);
        }
        catch { }

        // Summary table with conditional visuals
        var range = overview.TableFrom(sumRows, title: "Domains", configure: o => {
            o.HeaderCase = HeaderCase.Title;
        }, visuals: v => {
            // Numeric formatting
            v.NumericColumnFormats["Warnings"] = "0";
            v.NumericColumnFormats["Errors"] = "0";
            // Data bars for findings
            v.DataBars["Warnings"] = SixLabors.ImageSharp.Color.ParseHex("#FFA500"); // orange
            v.DataBars["Errors"] = SixLabors.ImageSharp.Color.ParseHex("#DC3545");   // red
            // Backgrounds for text statuses
            var ok = "#D1E7DD";      // light green
            var warn = "#FFF4CE";    // light yellow
            var err = "#F8D7DA";     // light red
            var none = "#E9ECEF";    // light gray
            foreach (var col in new[] { "MX", "SPF", "DKIM", "DMARC", "MTASTS", "TLSRPT", "DNSSEC", "RPKI" })
            {
                v.TextBackgrounds[col] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                    { "OK", ok }, { "Pass", ok }, { "Valid", ok },
                    { "Warning", warn }, { "Warn", warn },
                    { "Error", err }, { "Fail", err },
                    { "-", none }, { "None", none }, { "Missing", none }
                };
                v.BoldByText[col] = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase) { "Error", "Fail" };
            }
            v.FreezeHeaderRow = true;
        });

        // Add traffic light icon set to Errors column
        try
        {
            var coords = ParseRange(range ?? string.Empty);
            if (coords.startCol != 0)
            {
                // Errors is now the 11th column (after DNSSEC, RPKI)
                int errorsCol = coords.startCol + 11 - 1;
                string colLetter = IndexToCol(errorsCol);
                // Exclude header row
                string errRange = $"{colLetter}{coords.startRow + 1}:{colLetter}{coords.endRow}";
                overview.ConditionalIconSet(errRange, IconSetValues.ThreeTrafficLights1);
            }
        }
        catch { }
        overview.Finish(autoFitColumns: true);

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

            // Transport section (compact)
            if (b.Mtasts != null || b.TlsRpt != null)
            {
                s.SectionWithAnchor("Transport");
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
                if (tp.Count > 0) s.PropertiesGrid(tp.ToArray(), columns: 3);
            }

            // MailTLS Sources (Word parity)
            if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
            {
                s.SectionWithAnchor("MailTLS Sources");
                s.PropertiesGrid(new (string, object?)[] {
                    ("SMTP", b.SmtpTls?.Status ?? "-"),
                    ("IMAP", b.ImapTls?.Status ?? "-"),
                    ("POP",  b.PopTls?.Status ?? "-")
                }, columns: 3);

                // Detailed per-server tables per service
                void AddTlsServers(string title, DomainDetective.Views.MailTlsInfo? info)
                {
                    if (info == null || (info.Servers?.Count ?? 0) == 0) return;
                    s.Section($"{title} Servers");
                    var rows = info.Servers.Select(x => new {
                        Host = x.Key,
                        Status = info.Status ?? "-",
                        StartTLS = x.StartTlsAdvertised ? "Yes" : "No",
                        Grade = x.Grade.ToString(),
                        Protocol = x.Protocol,
                        TLS13 = x.Tls13Used ? "Yes" : (x.SupportsTls13 ? "Supported" : "No"),
                        CertValid = x.CertificateValid ? "Yes" : "No",
                        ChainValid = x.ChainValid ? "Yes" : "No",
                        HostnameMatch = x.HostnameMatch ? "Yes" : "No",
                        DaysToExpire = x.DaysToExpire
                    }).ToList();
                    s.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }
                AddTlsServers("SMTP", b.SmtpTls);
                AddTlsServers("IMAP", b.ImapTls);
                AddTlsServers("POP3", b.PopTls);
            }

            // MX details
            if (b.Mx != null)
            {
                var mx = b.Mx;
                s.SectionWithAnchor("MX");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", mx.MxRecordExists ? "Yes" : "No"),
                    ("IPv6 Supported", mx.Ipv6Supported ? "Yes" : "No"),
                    ("Has Backup Servers", mx.HasBackupServers ? "Yes" : "No"),
                    ("Null MX", mx.HasNullMx ? "Yes" : "No"),
                    ("Priorities In Order", mx.PrioritiesInOrder ? "Yes" : "No"),
                    ("Points to CNAME", mx.PointsToCname ? "Yes" : "No"),
                    ("Points to IP", mx.PointsToIpAddress ? "Yes" : "No"),
                    ("Target Consistent Across NS", mx.TargetAddressConsistentAcrossNs ? "Yes" : "No")
                }, columns: 3);
                if ((mx.MxRecords?.Count ?? 0) > 0)
                {
                    var mxRows = mx.MxRecords.Select(r => new { Host = r }).ToList();
                    s.TableFrom(mxRows, title: "MX Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
                }
                if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
                {
                    s.Section("MailTLS");
                    s.TableFrom(new [] {
                        new { Service = "SMTP", Status = b.SmtpTls?.Status ?? "-", Summary = b.SmtpTls?.Summary ?? string.Empty },
                        new { Service = "IMAP", Status = b.ImapTls?.Status ?? "-", Summary = b.ImapTls?.Summary ?? string.Empty },
                        new { Service = "POP3", Status = b.PopTls?.Status ?? "-", Summary = b.PopTls?.Summary ?? string.Empty },
                    }, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }
                if ((mx.Recommendations?.Count ?? 0) > 0) { s.Section("Recommendations"); s.BulletedListWithFill(mx.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
                if ((mx.Positives?.Count ?? 0) > 0) { s.Section("Positives"); s.BulletedList(mx.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
            }

            // SPF details (rich)
            if (b.Spf != null)
            {
                var spf = b.Spf;
                var sec = DomainDetective.Reports.SectionProjectors.BuildSpf(spf);
                s.SectionWithAnchor("SPF");
                var props = new System.Collections.Generic.List<(string, object?)> {
                    ("Status", spf.Status ?? "-"),
                    ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                    ("DNS Lookups", sec?.DnsLookupsCount ?? spf.DnsLookupsCount),
                };
                if (!string.IsNullOrWhiteSpace(spf.Raw?.AllMechanism)) props.Add(("All Mechanism", spf.Raw!.AllMechanism!));
                s.PropertiesGrid(props.ToArray(), columns: 3);

                // Positives
                if ((sec?.Positives.Count ?? 0) > 0) { s.Section("Positives"); s.BulletedList(sec!.Positives.ToArray()); }

                // Findings
                if ((sec?.Findings.Count ?? 0) > 0)
                {
                    var rows = sec!.Findings.Select(a => new { a.Severity, a.Code, a.Target, a.Message }).ToList();
                    s.TableFrom(rows, title: "Findings", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }

                // Evidence (SPF record)
                if (!string.IsNullOrWhiteSpace(sec?.SpfRecord))
                {
                    s.Section("Evidence");
                    s.PropertiesGrid(new (string, object?)[] { ("SPF Record", sec!.SpfRecord) }, columns: 1);
                }

                // Mechanisms table
                if ((sec?.Mechanisms.Count ?? 0) > 0)
                {
                    var mech = sec!.Mechanisms.Select(m => new { Qualifier = m.Qualifier, Type = m.Type, Value = m.Value, Provider = m.Provider }).ToList();
                    if (mech.Count > 200)
                    {
                        var sheetName = MakeUniqueSheetName($"{b.Subject}.SPF.Mechanisms", usedNames);
                        var mechSheet = new SheetComposer(doc, sheetName);
                        mechSheet.Title($"SPF Mechanisms — {b.Subject}");
                        mechSheet.TableFrom(mech, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                        mechSheet.Finish(autoFitColumns: true);
                        s.Section("Mechanisms");
                        s.PropertiesGrid(new (string, object?)[] { ("Rows", mech.Count), ("Sheet", sheetName) }, columns: 2);
                    }
                    else
                    {
                        s.TableFrom(mech, title: "Mechanisms", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                    }
                }

                // Flattened IP Analysis
                if ((sec?.FlattenedUniqueIpCount ?? 0) + (sec?.FlattenedDuplicateIpCount ?? 0) + (sec?.FlattenedTokenCount ?? 0) > 0)
                {
                    s.Section("Flattened IP Analysis");
                    s.PropertiesGrid(new (string, object?)[] {
                        ("Unique IPs", sec!.FlattenedUniqueIpCount),
                        ("Duplicate IPs", sec!.FlattenedDuplicateIpCount),
                        ("Tokens Resolved", sec!.FlattenedTokenCount),
                    }, columns: 3);
                }

                // Provider Help (SPF)
                if ((sec?.ProviderHelp.Count ?? 0) > 0)
                {
                    s.Section("Provider Help");
                    var links = sec!.ProviderHelp.Take(8).Select(t => new { Title = t.Title, Url = t.Url }).ToList();
                    var a1 = s.TableFrom(links, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                    try
                    {
                        foreach (var row in s.Sheet.RowsObjects(a1))
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

        // DNSBL details
        if (b.Dnsbl != null)
        {
            var db = b.Dnsbl;
            s.SectionWithAnchor("DNSBL");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Providers Checked", db.ProvidersChecked),
                    ("Hosts Checked", db.HostsChecked),
                    ("Hosts Listed", db.HostsListed)
                }, columns: 3);
                if (db.HostSummaries != null && db.HostSummaries.Count > 0)
                {
                    var hostRows = db.HostSummaries.Select(h => new { Host = h.Key, Listed = h.Listed, Total = h.Total, Blacklists = string.Join(", ", h.Blacklists ?? new List<string>()) }).ToList();
                    s.TableFrom(hostRows, title: "Host Summaries", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                        v.NumericColumnFormats["Listed"] = "0"; v.NumericColumnFormats["Total"] = "0"; v.FreezeHeaderRow = true;
                    });
                }
            }

            // NS details
            if (b.Ns != null)
            {
                var ns = b.Ns;
                s.SectionWithAnchor("NS");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", ns.NsRecordExists ? "Yes" : "No"),
                    ("At Least Two", ns.AtLeastTwoRecords ? "Yes" : "No"),
                    ("All Have A/AAAA", ns.AllHaveAOrAaaa ? "Yes" : "No"),
                    ("Glue Complete", ns.GlueRecordsComplete ? "Yes" : "No"),
                    ("Glue Consistent", ns.GlueRecordsConsistent ? "Yes" : "No"),
                    ("Delegation Matches", ns.DelegationMatches ? "Yes" : "No"),
                    ("Distinct ASNs", ns.AsnDistinctCount)
                }, columns: 3);
                if ((ns.NsRecords?.Count ?? 0) > 0)
                {
                    s.TableFrom(ns.NsRecords.Select(x => new { NS = x }).ToList(), title: "NS Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }
                if ((ns.ParentNsRecords?.Count ?? 0) > 0)
                {
                    s.TableFrom(ns.ParentNsRecords.Select(x => new { ParentNS = x }).ToList(), title: "Parent NS Records", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }
            }

            // SOA details
            if (b.Soa != null)
            {
                var soa = b.Soa;
                s.SectionWithAnchor("SOA");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Primary NS", soa.PrimaryNameServer),
                    ("Responsible", soa.ResponsibleMailbox),
                    ("Serial", soa.SerialNumber),
                    ("Serial Format", soa.SerialFormatValid ? "Valid" : "Check"),
                    ("Refresh", soa.Refresh), ("Retry", soa.Retry), ("Expire", soa.Expire),
                    ("Minimum", soa.Minimum), ("Neg Cache TTL", soa.NegativeCacheTtl)
                }, columns: 3);
            }

            // CAA details
            if (b.Caa != null)
            {
                var caa = b.Caa;
                s.SectionWithAnchor("CAA");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Valid Records", caa.ValidRecords),
                    ("Invalid Records", caa.InvalidRecords),
                    ("Conflicting", caa.Conflicting ? "Yes" : "No"),
                    ("Duplicate Issuers", caa.HasDuplicateIssuers ? "Yes" : "No")
                }, columns: 3);
                if ((caa.CanIssueCertificatesForDomain?.Count ?? 0) > 0)
                { s.Section("Allowed CAs"); s.BulletedList(caa.CanIssueCertificatesForDomain); }
                if ((caa.CanIssueWildcardCertificatesForDomain?.Count ?? 0) > 0)
                { s.Section("Allowed Wildcard CAs"); s.BulletedList(caa.CanIssueWildcardCertificatesForDomain); }
                if ((caa.CanIssueMail?.Count ?? 0) > 0)
                { s.Section("Mail CAA Values"); s.BulletedList(caa.CanIssueMail); }
                if ((caa.ReportViolationEmail?.Count ?? 0) > 0)
                { s.Section("Report-To Emails"); s.BulletedList(caa.ReportViolationEmail); }
            }

            // RPKI details
            if (b.Rpki != null)
            {
                var rp = b.Rpki;
                s.SectionWithAnchor("RPKI");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Total Checked", rp.TotalChecked), ("Valid", rp.ValidCount), ("All Valid", rp.AllValid ? "Yes" : "No")
                }, columns: 3);
                if ((rp.Results?.Count ?? 0) > 0)
                {
                    var rpRows = rp.Results.Select(r => new { r.IpAddress, r.Prefix, r.Asn, Valid = r.Valid ? "Yes" : "No" }).ToList();
                    s.TableFrom(rpRows, title: "RPKI Results", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Asn"] = "0"; v.FreezeHeaderRow = true; });
                }
            }

            // Zone Transfer / Wildcard
            if (b.ZoneTransfer != null)
            {
                var zt = b.ZoneTransfer;
                s.SectionWithAnchor("Zone Transfer");
                s.PropertiesGrid(new (string, object?)[] { ("Open", $"{zt.OpenCount}/{zt.TotalChecked}") }, columns: 3);
                if ((zt.ServerResults?.Count ?? 0) > 0)
                {
                    var zRows = zt.ServerResults.Select(kv2 => new { Server = kv2.Key, Open = kv2.Value ? "Yes" : "No" }).ToList();
                    s.TableFrom(zRows, title: "Servers", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => v.FreezeHeaderRow = true);
                }
            }
            if (b.Wildcard != null)
            {
                var wc = b.Wildcard;
                s.SectionWithAnchor("Wildcard DNS");
                s.PropertiesGrid(new (string, object?)[] { ("Catch-All", wc.CatchAll ? "Yes" : "No") }, columns: 3);
                if ((wc.TestedNames?.Count ?? 0) > 0)
                { s.Section("Tested Names"); s.BulletedList(wc.TestedNames); }
                if ((wc.ResolvedNames?.Count ?? 0) > 0)
                { s.Section("Resolved Names"); s.BulletedList(wc.ResolvedNames); }
            }
            // DNSSEC / DANE summaries
            if (b.Dnssec != null || b.Dane != null)
            {
                s.SectionWithAnchor("DNSSEC/DANE");
                var rows = new List<(string, object?)>();
                if (b.Dnssec != null)
                {
                    rows.Add(("DNSSEC", b.Dnssec.Status ?? "-"));
                }
                if (b.Dane != null)
                {
                    rows.Add(("DANE", b.Dane.Status ?? "-"));
                }
                if (rows.Count > 0) s.PropertiesGrid(rows.ToArray(), columns: 3);
            }

            // Mail TLS (SMTP/IMAP/POP3)
            if (b.SmtpTls != null || b.ImapTls != null || b.PopTls != null)
            {
                s.SectionWithAnchor("Mail TLS");
                void RenderTls(string label, DomainDetective.Views.MailTlsInfo info)
                {
                    if (info == null) return;
                    s.Section(label);
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
                        s.TableFrom(rows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => {
                            v.NumericColumnFormats["DaysToExp"] = "0"; v.FreezeHeaderRow = true;
                            v.TextBackgrounds["Grade"] = new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase) {
                                { "A", "#D1E7DD" }, { "B", "#E2E3FF" }, { "C", "#FFF4CE" }, { "D", "#F8D7DA" }, { "F", "#F8D7DA" }
                            };
                        });
                    }
                }
                if (b.SmtpTls != null) RenderTls("SMTP", b.SmtpTls);
                if (b.ImapTls != null) RenderTls("IMAP", b.ImapTls);
                if (b.PopTls != null) RenderTls("POP3", b.PopTls);
            }

            // ARC (Authenticated Received Chain)
            if (b.Arc != null)
            {
                var arc = b.Arc;
                s.SectionWithAnchor("ARC");
                s.PropertiesGrid(new (string, object?)[] {
                    ("ARC Headers Present", arc.ArcHeadersFound ? "Yes" : "No"),
                    ("Seal Count", arc.SealCount),
                    ("AAR Count", arc.AarCount),
                    ("Valid Chain", arc.ValidChain ? "Yes" : "No"),
                    ("Chain State", arc.ChainState)
                }, columns: 3);
                if ((arc.Highlights?.Count ?? 0) > 0) { s.Section("Highlights"); s.BulletedList(arc.Highlights); }
                if ((arc.Recommendations?.Count ?? 0) > 0) { s.Section("Recommendations"); s.BulletedListWithFill(arc.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
            }

            // BIMI details
            if (b.Bimi != null)
            {
                var bi = b.Bimi;
                s.SectionWithAnchor("BIMI");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", bi.BimiRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", bi.StartsCorrectly ? "Yes" : "No"),
                    ("Location", string.IsNullOrWhiteSpace(bi.Location) ? "-" : bi.Location),
                    ("Authority", string.IsNullOrWhiteSpace(bi.Authority) ? "-" : bi.Authority),
                    ("SVG Valid", bi.SvgValid ? "Yes" : (string.IsNullOrWhiteSpace(bi.SvgInvalidReason) ? "No" : $"No: {bi.SvgInvalidReason}")),
                    ("VMC Present", bi.ValidVmc ? "Yes" : "No")
                }, columns: 3);
            }

            // SPF details
            if (b.Spf != null)
            {
                var spf = b.Spf;
                s.SectionWithAnchor("SPF");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", spf.SpfRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", spf.StartsCorrectly ? "Yes" : "No"),
                    ("DNS Lookups", spf.DnsLookupsCount),
                    ("Exceeds Lookup Limit", spf.ExceedsDnsLookups ? "Yes" : "No"),
                    ("Multiple 'all'", spf.MultipleAllMechanisms ? "Yes" : "No"),
                    ("Multiple SPF Records", spf.MultipleSpfRecords ? "Yes" : "No"),
                    ("Record Length", spf.RecordLength),
                    ("Size Limit", (spf.ExceedsTotalCharacterLimit || spf.ExceedsCharacterLimit) ? "Exceeded" : "OK"),
                    ("Unknown Mechanisms", spf.UnknownMechanisms?.Count ?? 0)
                }, columns: 3);

                // Mechanisms table (Prefix, Type, Value, Provider, Source, Depth)
                if (spf.Mechanisms != null && spf.Mechanisms.Count > 0)
                {
                    var mechRows = spf.Mechanisms.Select(m => new {
                        Prefix = m.Prefix,
                        Type = m.Type,
                        Value = m.Value,
                        Provider = string.IsNullOrWhiteSpace(m.Provider) ? "" : m.Provider,
                        Source = string.IsNullOrWhiteSpace(m.SourceDomain) ? spf.Subject : m.SourceDomain,
                        Depth = m.Depth
                    }).ToList();
                    s.TableFrom(mechRows, title: "Mechanisms", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnFormats["Depth"] = "0"; v.FreezeHeaderRow = true; });
                }

                // Highlights / Recommendations
                if ((spf.Highlights?.Count ?? 0) > 0)
                { s.Section("Highlights"); s.BulletedList(spf.Highlights); }
                if ((spf.Recommendations?.Count ?? 0) > 0)
                { s.Section("Recommendations"); s.BulletedListWithFill(spf.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
                if ((spf.Positives?.Count ?? 0) > 0)
                { s.Section("Positives"); s.BulletedList(spf.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
            }

            // DMARC details
            if (b.Dmarc != null)
            {
                var d = b.Dmarc;
                s.SectionWithAnchor("DMARC");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Record Present", d.DmarcRecordExists ? "Yes" : "No"),
                    ("Starts Correctly", d.StartsCorrectly ? "Yes" : "No"),
                    ("Policy (p)", d.Policy ?? "-"),
                    ("Subdomain Policy (sp)", d.SubPolicy ?? "-"),
                    ("Percent (pct)", d.Percent ?? "-"),
                    ("Alignment", $"dkim={d.DkimAlignment ?? "?"} / spf={d.SpfAlignment ?? "?"}"),
                    ("Public Suffix Policy", string.IsNullOrWhiteSpace(d.PublicSuffixPolicy) ? "-" : d.PublicSuffixPolicy),
                    ("Nonexistent Policy", string.IsNullOrWhiteSpace(d.NonexistentPolicy) ? "-" : d.NonexistentPolicy),
                    ("Is Policy Valid", d.IsPolicyValid ? "Yes" : "No")
                }, columns: 3);

                // RUA/RUF lists
                if ((d.MailtoRua?.Count ?? 0) > 0 || (d.HttpRua?.Count ?? 0) > 0)
                {
                    s.Section("RUA Destinations");
                    var list = new List<string>();
                    if (d.MailtoRua != null) list.AddRange(d.MailtoRua);
                    if (d.HttpRua != null) list.AddRange(d.HttpRua);
                    s.BulletedList(list);
                }
                if ((d.MailtoRuf?.Count ?? 0) > 0 || (d.HttpRuf?.Count ?? 0) > 0)
                {
                    s.Section("RUF Destinations");
                    var list = new List<string>();
                    if (d.MailtoRuf != null) list.AddRange(d.MailtoRuf);
                    if (d.HttpRuf != null) list.AddRange(d.HttpRuf);
                    s.BulletedList(list);
                }
                if ((d.DeprecatedTags?.Count ?? 0) > 0)
                { s.Section("Deprecated Tags"); s.BulletedList(d.DeprecatedTags); }
                if ((d.Recommendations?.Count ?? 0) > 0)
                { s.Section("Recommendations"); s.BulletedListWithFill(d.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE"); }
                if ((d.Positives?.Count ?? 0) > 0)
                { s.Section("Positives"); s.BulletedList(d.Positives.Select(p => p.Title ?? p.Code).ToArray()); }
                if ((d.Highlights?.Count ?? 0) > 0)
                { s.Section("Highlights"); s.BulletedList(d.Highlights); }
            }

            // DKIM details (handled later below with evidence table)

            if (b.Classification != null)
            {
                s.SectionWithAnchor("Classification");
                s.PropertiesGrid(new (string, object?)[] {
                    ("Category", b.Classification.Classification),
                    ("Confidence", b.Classification.Confidence),
                    ("Status", b.Classification.Status)
                }, columns: 3);
                if (b.Classification.ScoreBreakdown != null && b.Classification.ScoreBreakdown.Count > 0)
                {
                    var rows = b.Classification.ScoreBreakdown.Select(kv2 => new { Name = kv2.Key, Value = kv2.Value }).ToList();
                    s.TableFrom(rows, title: "Score Breakdown", configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.NumericColumnDecimals["Value"] = 2; });
                }
                if (b.Classification.Recommendations?.Count > 0)
                {
                    s.SectionWithAnchor("Recommendations");
                    s.BulletedListWithFill(b.Classification.Recommendations.Select(r => r.Title ?? r.Code).ToArray(), fillHex: "#FFF4CE");
                }
            }
            s.Finish(autoFitColumns: true);
        }

        // (duplicate DKIM/DMARC detail blocks removed — handled earlier within the per-domain sheet scope)

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
            recSheet.TableFrom(recRows, title: null, configure: o => { o.HeaderCase = HeaderCase.Title; }, visuals: v => { v.FreezeHeaderRow = true; });
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
            }
            refSheet.Finish(autoFitColumns: true);
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

    // Adapter: map shared DomainBucket to local Excel DomainBucket structure
    private static DomainBucket Map(CompositionBuilder.DomainBucket s)
    {
        var b = new DomainBucket {
            Subject = s.Subject,
            Mx = s.Mx,
            Spf = s.Spf,
            Dmarc = s.Dmarc,
            Mtasts = s.Mtasts,
            TlsRpt = s.TlsRpt,
            Dnsbl = s.Dnsbl,
            Dnssec = s.Dnssec,
            Dane = s.Dane,
            SmtpTls = s.SmtpTls,
            ImapTls = s.ImapTls,
            PopTls = s.PopTls,
            Ns = s.Ns,
            Soa = s.Soa,
            Caa = s.Caa,
            Rpki = s.Rpki,
            ZoneTransfer = s.ZoneTransfer,
            Wildcard = s.Wildcard,
            Classification = s.Classification
        };
        if (s.Dkim != null && s.Dkim.Count > 0) b.Dkim.AddRange(s.Dkim);
        return b;
    }

    private static string? TryGetSubject(object item)
    {
        try { var p = item.GetType().GetProperty("Subject"); return p?.GetValue(item) as string; } catch { return null; }
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

    // Helpers for A1 range parsing (e.g., "B4:J27")
    private struct RangeCoords
    {
        public int startCol, startRow, endCol, endRow;
        public RangeCoords(int sc, int sr, int ec, int er) { startCol = sc; startRow = sr; endCol = ec; endRow = er; }
    }
    private static RangeCoords ParseRange(string a1)
    {
        if (string.IsNullOrWhiteSpace(a1)) return default;
        var parts = a1.Split(':');
        if (parts.Length != 2) return default;
        var (sc, sr) = A1ToCoord(parts[0]);
        var (ec, er) = A1ToCoord(parts[1]);
        if (sc <= 0 || sr <= 0 || ec <= 0 || er <= 0) return default;
        return new RangeCoords(Math.Min(sc, ec), Math.Min(sr, er), Math.Max(sc, ec), Math.Max(sr, er));
    }
    private static (int col, int row) A1ToCoord(string cell)
    {
        if (string.IsNullOrWhiteSpace(cell)) return (0, 0);
        int i = 0; int col = 0;
        while (i < cell.Length && char.IsLetter(cell[i])) { col = col * 26 + (char.ToUpperInvariant(cell[i]) - 'A' + 1); i++; }
        int row = 0; while (i < cell.Length && char.IsDigit(cell[i])) { row = row * 10 + (cell[i] - '0'); i++; }
        return (col, row);
    }
    private static string IndexToCol(int index)
    {
        if (index <= 0) return "A";
        string s = string.Empty;
        while (index > 0)
        {
            index--; s = (char)('A' + (index % 26)) + s; index /= 26;
        }
        return s;
    }
}
