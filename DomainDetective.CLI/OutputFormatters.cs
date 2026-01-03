using DomainDetective;
using Spectre.Console;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text;
using System.Linq;

namespace DomainDetective.CLI;

internal static class OutputFormatters {
    internal static void FormatAsRichTable(string domain, DomainHealthCheck hc, HealthCheckType[] checks) {
        var resultTable = new Table() {
            Border = TableBorder.Rounded,
            Title = new TableTitle($"[bold green]Analysis Results for {domain}[/]")
        };
        
        resultTable.AddColumn(new TableColumn("[bold]Check[/]").Centered());
        resultTable.AddColumn(new TableColumn("[bold]Status[/]").Centered());
        resultTable.AddColumn(new TableColumn("[bold]Key Findings[/]"));
        
        foreach (var check in checks) {
            var (status, findings) = GetCheckSummary(hc, check);
            if (status != null) {
                var statusColor = GetStatusColor(status);
                resultTable.AddRow(
                    $"[cyan]{check}[/]",
                    $"[{statusColor}]{status}[/]",
                    findings ?? "[dim]No data[/]"
                );
            }
        }
        
        AnsiConsole.Write(resultTable);
    }
    
    internal static void FormatAsSummaryCards(string domain, DomainHealthCheck hc) {
        var grid = new Grid();
        grid.AddColumn();
        grid.AddColumn();
        grid.AddColumn();
        
        var cards = new List<Panel>();
        
        // Email Security Card
        var emailCard = CreateSummaryCard("📧 Email Security", new[] {
            ("SPF", GetCheckStatus(hc.SpfAnalysis)),
            ("DKIM", GetCheckStatus(hc.DKIMAnalysis)),
            ("DMARC", GetCheckStatus(hc.DmarcAnalysis)),
            ("MX Records", GetCheckStatus(hc.MXAnalysis))
        });
        cards.Add(emailCard);
        
        // DNS Security Card
        var dnsCard = CreateSummaryCard("🔒 DNS Security", new[] {
            ("DNSSEC", GetCheckStatus(hc.DnsSecAnalysis)),
            ("CAA", GetCheckStatus(hc.CAAAnalysis)),
            ("DANE", GetCheckStatus(hc.DaneAnalysis)),
            ("NS Records", GetCheckStatus(hc.NSAnalysis))
        });
        cards.Add(dnsCard);
        
        // Certificate Card
        if (hc.CertificateAnalysis != null && hc.CertificateAnalysis.IsReachable) {
            var certCard = CreateSummaryCard("🔐 Certificate", new[] {
                ("URL", hc.CertificateAnalysis.Url ?? "Unknown"),
                ("Valid", hc.CertificateAnalysis.IsValid ? "✅ Yes" : "❌ No"),
                ("Days to Expire", hc.CertificateAnalysis.DaysToExpire.ToString()),
                ("Self-Signed", hc.CertificateAnalysis.IsSelfSigned ? "⚠️ Yes" : "✅ No")
            });
            cards.Add(certCard);
        }
        
        // Add cards to grid in rows of 3
        for (int i = 0; i < cards.Count; i += 3) {
            var row = new List<Panel>();
            for (int j = 0; j < 3 && i + j < cards.Count; j++) {
                row.Add(cards[i + j]);
            }
            while (row.Count < 3) {
                row.Add(new Panel(" ") { Border = BoxBorder.None });
            }
            grid.AddRow(row.ToArray());
        }
        
        AnsiConsole.Write(grid);
    }
    
    private static Panel CreateSummaryCard(string title, (string name, string value)[] items) {
        var table = new Table() {
            Border = TableBorder.None,
            ShowHeaders = false
        };
        table.AddColumn("");
        table.AddColumn("");
        
        foreach (var (name, value) in items) {
            table.AddRow($"[dim]{name}:[/]", value);
        }
        
        return new Panel(table) {
            Header = new PanelHeader(title),
            Border = BoxBorder.Rounded,
            Padding = new Padding(1)
        };
    }
    
    private static string GetCheckStatus(object? analysis) {
        if (analysis == null) return "[dim]Not checked[/]";
        
        var type = analysis.GetType();
        var issuesProperty = type.GetProperty("Issues");
        var validProperty = type.GetProperty("IsValid");
        var recordProperty = type.GetProperty("Record");
        var recordsProperty = type.GetProperty("Records");
        
        if (validProperty != null) {
            var isValid = validProperty.GetValue(analysis) as bool?;
            return isValid == true ? "[green]✅ Valid[/]" : "[red]❌ Invalid[/]";
        }
        
        if (issuesProperty != null) {
            var issues = issuesProperty.GetValue(analysis) as System.Collections.IList;
            if (issues != null && issues.Count > 0) {
                return $"[yellow]⚠ {issues.Count} issue(s)[/]";
            }
        }
        
        if (recordProperty != null || recordsProperty != null) {
            var hasRecord = recordProperty?.GetValue(analysis) != null || 
                           (recordsProperty?.GetValue(analysis) as System.Collections.IList)?.Count > 0;
            return hasRecord ? "[green]✅ Present[/]" : "[yellow]⚠ Not found[/]";
        }
        
        return "[green]✅ OK[/]";
    }
    
    private static (string? status, string? findings) GetCheckSummary(DomainHealthCheck hc, HealthCheckType check) {
        var data = GetCheckData(hc, check);
        if (data == null) return (null, null);
        
        var type = data.GetType();
        var issuesProperty = type.GetProperty("Issues");
        var issues = issuesProperty?.GetValue(data) as System.Collections.IList;
        
        string status = "✅ OK";
        var findings = new List<string>();
        
        if (issues != null && issues.Count > 0) {
            status = issues.Count > 2 ? "❌ Failed" : "⚠️  Warning";
            foreach (var issue in issues) {
                findings.Add($"• {issue}");
                if (findings.Count >= 3) {
                    findings.Add($"• ... and {issues.Count - 3} more");
                    break;
                }
            }
        } else {
            findings.Add(GetPositiveFinding(check, data));
        }

        // Inline Autodiscover endpoint verdict summary
        if (check == HealthCheckType.AUTODISCOVER)
        {
            try {
                var endpoints = hc.AutodiscoverHttpAnalysis?.Endpoints;
                if (endpoints != null && endpoints.Count > 0)
                {
                    var count = endpoints.Count;
                    var winner = endpoints.FirstOrDefault(e => e.XmlValid) ??
                                 endpoints.FirstOrDefault(e => e.JsonValid) ??
                                 endpoints.FirstOrDefault();
                    var best = winner?.FinalHost ?? new Uri(winner?.Url ?? "http://invalid").Host;
                    var verdict = (winner?.XmlValid == true) ? "XML" : (winner?.JsonValid == true) ? "JSON" : "None";
                    findings.Add($"• Endpoints: {count}; Best host: {best}; Valid: {verdict}");
                }
            } catch { /* ignore summarization errors */ }
        }

        // Inline HTTP: summarize detected technologies and 3P hosts
        if (check == HealthCheckType.HTTP)
        {
            try
            {
                var ws = hc.WebStaticScanAnalysis;
                if (ws != null && ws.TechDetails != null && ws.TechDetails.Count > 0)
                {
                    // Group by technology; pick representative category/source/version
                    var techs = ws.TechDetails
                        .GroupBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
                        .Select(g => {
                            var first = g.First();
                            return new { Name = g.Key, Cat = first.Category.ToString(), Src = first.SourceKind.ToString(), Ver = first.Version, Conf = first.Confidence };
                        })
                        .OrderBy(x => x.Name)
                        .Take(8)
                        .ToArray();
                    if (techs.Length > 0)
                    {
                        var items = techs.Select(t => string.IsNullOrWhiteSpace(t.Ver)
                            ? $"{t.Name} ({t.Cat}, {t.Src}, c{t.Conf})"
                            : $"{t.Name} {t.Ver} ({t.Cat}, {t.Src}, c{t.Conf})");
                        findings.Add("• Tech: " + string.Join("; ", items));
                    }
                    // Top third-party hosts
                    var third = ws.Hosts.Values.Where(h => !h.FirstParty)
                        .OrderByDescending(h => h.Bytes)
                        .Take(3)
                        .Select(h => h.Host)
                        .ToArray();
                    if (third.Length > 0)
                    {
                        findings.Add("• Top 3P: " + string.Join(", ", third));
                    }
                    // HTTPS ratio
                    var reqTotal = ws.Requests.Count;
                    if (reqTotal > 0)
                    {
                        int https = 0;
                        foreach (var r in ws.Requests) { try { var u = new Uri(r.FinalUrl ?? r.Url); if (u.Scheme == "https") https++; } catch { } }
                        var pct = (int)Math.Round(100.0 * https / reqTotal);
                        findings.Add($"• HTTPS: {pct}% of {reqTotal} resources");
                    }
                    // (redirect chain intentionally not included in CLI summary per current scope)
                }
            }
            catch { /* summary best-effort */ }
        }

        return (status, string.Join("\n", findings));
    }
    
    private static string GetPositiveFinding(HealthCheckType check, object data) {
        return check switch {
            HealthCheckType.SPF => "SPF record properly configured",
            HealthCheckType.DMARC => "DMARC policy is active",
            HealthCheckType.DKIM => "DKIM selectors found",
            HealthCheckType.MX => "Mail servers configured",
            HealthCheckType.DNSSEC => "DNSSEC enabled",
            HealthCheckType.CAA => "CAA records present",
            _ => "Check passed"
        };
    }
    
    private static string GetStatusColor(string status) {
        return status switch {
            var s when s.Contains("✅") => "green",
            var s when s.Contains("⚠") => "yellow",
            var s when s.Contains("❌") => "red",
            _ => "white"
        };
    }
    
    private static object? GetCheckData(DomainHealthCheck hc, HealthCheckType check) {
        return check switch {
            HealthCheckType.DMARC => hc.DmarcAnalysis,
            HealthCheckType.SPF => hc.SpfAnalysis,
            HealthCheckType.DKIM => hc.DKIMAnalysis,
            HealthCheckType.MX => hc.MXAnalysis,
            HealthCheckType.REVERSEDNS => hc.ReverseDnsAnalysis,
            HealthCheckType.FCRDNS => hc.FcrDnsAnalysis,
            HealthCheckType.CAA => hc.CAAAnalysis,
            HealthCheckType.NS => hc.NSAnalysis,
            HealthCheckType.DELEGATION => hc.NSAnalysis,
            HealthCheckType.ZONETRANSFER => hc.ZoneTransferAnalysis,
            HealthCheckType.DANE => hc.DaneAnalysis,
            HealthCheckType.DNSBL => hc.DNSBLAnalysis,
            HealthCheckType.DNSSEC => hc.DnsSecAnalysis,
            HealthCheckType.AUTODISCOVER => hc.AutodiscoverAnalysis,
            HealthCheckType.CONTACT => hc.ContactInfoAnalysis,
            HealthCheckType.ARC => hc.ArcAnalysis,
            HealthCheckType.DANGLINGCNAME => hc.DanglingCnameAnalysis,
            HealthCheckType.SMTPBANNER => hc.SmtpBannerAnalysis,
            HealthCheckType.IMAPTLS => hc.ImapTlsAnalysis,
            HealthCheckType.POP3TLS => hc.Pop3TlsAnalysis,
            HealthCheckType.PORTAVAILABILITY => hc.PortAvailabilityAnalysis,
            HealthCheckType.PORTSCAN => hc.PortScanAnalysis,
            HealthCheckType.IPNEIGHBOR => hc.IPNeighborAnalysis,
            HealthCheckType.DNSTUNNELING => hc.DnsTunnelingAnalysis,
            HealthCheckType.WILDCARDDNS => hc.WildcardDnsAnalysis,
            HealthCheckType.EDNSSUPPORT => hc.EdnsSupportAnalysis,
            HealthCheckType.DNSAMPLIFICATION => hc.DnsAmplificationAnalysis,
            HealthCheckType.DNSOVERTLS => hc.DnsOverTlsAnalysis,
            _ => null
        };
    }
    
    internal static void ExportToJson(DomainHealthCheck hc, string filePath) {
        var json = hc.ToJson();
        File.WriteAllText(filePath, json);
        AnsiConsole.MarkupLine($"[green]Results exported to {filePath}[/]");
    }
    
    [RequiresUnreferencedCode("Calls GenerateHtmlReport which uses System.Text.Json.JsonSerializer.Serialize")]
    [RequiresDynamicCode("Calls GenerateHtmlReport which uses System.Text.Json.JsonSerializer.Serialize")]
    internal static void ExportToHtml(string domain, DomainHealthCheck hc, string filePath) {
        var html = GenerateHtmlReport(domain, hc);
        File.WriteAllText(filePath, html);
        AnsiConsole.MarkupLine($"[green]HTML report exported to {filePath}[/]");
    }
    
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    private static string GenerateHtmlReport(string domain, DomainHealthCheck hc) {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html>");
        sb.AppendLine("<head>");
        sb.AppendLine($"<title>Domain Analysis Report - {domain}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }");
        sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        sb.AppendLine("h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }");
        sb.AppendLine("h2 { color: #666; margin-top: 30px; }");
        sb.AppendLine(".check { margin: 20px 0; padding: 15px; border-left: 4px solid #ddd; background: #fafafa; }");
        sb.AppendLine(".check.success { border-color: #4CAF50; }");
        sb.AppendLine(".check.warning { border-color: #FFC107; }");
        sb.AppendLine(".check.error { border-color: #F44336; }");
        sb.AppendLine(".status { font-weight: bold; margin-bottom: 10px; }");
        sb.AppendLine(".status.success { color: #4CAF50; }");
        sb.AppendLine(".status.warning { color: #FFC107; }");
        sb.AppendLine(".status.error { color: #F44336; }");
        sb.AppendLine(".details { margin-top: 10px; }");
        sb.AppendLine(".issue { color: #F44336; margin: 5px 0; }");
        sb.AppendLine("pre { background: #f0f0f0; padding: 10px; border-radius: 4px; overflow-x: auto; }");
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("<div class='container'>");
        sb.AppendLine($"<h1>Domain Analysis Report: {domain}</h1>");
        sb.AppendLine($"<p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        
        // Add summary
        var summary = hc.BuildSummary();
        if (summary != null) {
            sb.AppendLine("<h2>Summary</h2>");
            sb.AppendLine("<pre>" + JsonSerializer.Serialize(summary, DomainDetective.Helpers.JsonOptions.Default) + "</pre>");
        }
        
        // Add individual check results
        sb.AppendLine("<h2>Detailed Results</h2>");
        
        foreach (var check in Enum.GetValues<HealthCheckType>()) {
            var data = GetCheckData(hc, check);
            if (data != null) {
                var (status, findings) = GetCheckSummary(hc, check);
                var cssClass = status?.Contains("✅") == true ? "success" : 
                              status?.Contains("⚠") == true ? "warning" : "error";
                
                sb.AppendLine($"<div class='check {cssClass}'>");
                sb.AppendLine($"<h3>{check}</h3>");
                sb.AppendLine($"<div class='status {cssClass}'>{status}</div>");
                if (!string.IsNullOrEmpty(findings)) {
                    sb.AppendLine($"<div class='details'>{findings.Replace("\n", "<br>")}</div>");
                }
                sb.AppendLine("</div>");
            }
        }
        
        sb.AppendLine("</div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
        
        return sb.ToString();
    }
}
