using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Views;
using Spectre.Console;
using Spectre.Console.Rendering;


namespace DomainDetective.CLI.Wizard;

internal static class FxLog
{
    private static readonly Channel<string> _bus = Channel.CreateUnbounded<string>();
    public static void Enqueue(string markup) => _bus.Writer.TryWrite(markup);
    public static async Task ConsumeAsync(CancellationToken ct)
    {
        await foreach (var line in _bus.Reader.ReadAllAsync(ct))
            await Fx.TypeLineAsync(line);
    }
    public static async Task ConsumeAsync(Func<string, Task> sink, CancellationToken ct)
    {
        await foreach (var line in _bus.Reader.ReadAllAsync(ct))
            await sink(line);
    }
    public static void Complete() => _bus.Writer.TryComplete();
}

internal static class Fx
{
    internal sealed class MailPolicyScore { public int SpfCoverage { get; set; } public int DkimSelectors { get; set; } public int DmarcStrength { get; set; } public int TransportTlsPosture { get; set; } }
    private sealed class LiveModel { public ProgressTask? Dns = null; public ProgressTask? Mail = null; public ProgressTask? Web = null; public ProgressTask? Rep = null; }

public static void TitleScreen(string domain, bool matrix, string persona)
    {
        var fig = new FigletText("DomainDetective").Color(Color.Green);
        var header = new Panel(fig)
        {
            Border = BoxBorder.Double,
            Header = new PanelHeader("[bold yellow]Hacker Wizard[/]"),
            BorderStyle = new Style(Color.Green)
        };
        AnsiConsole.Write(header);
        var info = new Panel(new Markup($"[green]Target:[/] [bold]{domain.EscapeMarkup()}[/]\n[grey]Mode:[/] [bold]Interactive[/] {(matrix ? "[green]// Matrix[/]" : string.Empty)}\n[grey]Persona:[/] [bold]{persona.EscapeMarkup()}[/]"))
        {
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Grey)
        };
        AnsiConsole.Write(info);
        AnsiConsole.WriteLine();
    }

    public static async Task TypeLineAsync(string markup, int delayMs = 6)
    {
        foreach (var ch in markup)
        {
            AnsiConsole.Markup(ch.ToString());
            await Task.Delay(delayMs);
        }
        AnsiConsole.WriteLine();
    }

    public static async Task RunSequentialLiveAsync(
        string domain,
        IReadOnlyList<(string Title, Func<Task> Run, bool Enabled)> stages,
        Func<string[]> getLogs,
        bool matrix,
        CancellationToken ct)
    {
        var tick = 0;
        var rnd = new Random();
        var spinnerFrames = new[] { "|", "/", "-", "\\" };
        var stagesState = stages.Select(s => new StageState(s.Title, s.Enabled)).ToArray();

        var uiCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var liveTask = AnsiConsole.Live(new Panel(""))
            .AutoClear(false)
            .StartAsync(async ctx =>
            {
                while (!uiCts.IsCancellationRequested)
                {
                    tick++;
                    // Render
                    var content = RenderDashboard(domain, stagesState, getLogs(), spinnerFrames[tick % spinnerFrames.Length], matrix, rnd);
                    ctx.UpdateTarget(content);
                    await Task.Delay(100, uiCts.Token).ContinueWith(_ => { });
                }
            });

        // Run stages sequentially with animated progress
        for (int i = 0; i < stages.Count; i++)
        {
            var s = stages[i];
            var st = stagesState[i];
            if (!s.Enabled)
            {
                st.Status = StageStatus.Skipped;
                st.Progress = 100;
                continue;
            }

            st.Status = StageStatus.Running;
            var task = s.Run();
            while (!task.IsCompleted)
            {
                st.Progress = Math.Min(99, st.Progress + 0.7);
                await Task.Delay(150, ct);
            }
            // Await to propagate exceptions
            await task;
            st.Progress = 100;
            st.Status = StageStatus.Done;
        }

        uiCts.Cancel();
        try { await liveTask; } catch { }
    }

    private enum StageStatus { Pending, Running, Done, Skipped }
    private sealed class StageState
    {
        public StageState(string title, bool enabled) { Title = title; Enabled = enabled; }
        public string Title { get; }
        public bool Enabled { get; }
        public double Progress { get; set; }
        public StageStatus Status { get; set; } = StageStatus.Pending;
    }

    private static IRenderable RenderDashboard(
        string domain,
        StageState[] stages,
        string[] logs,
        string spinner,
        bool matrix,
        Random rnd)
    {
        // Header
        var header = new Panel(new Markup($"[bold green]Scanning[/] [white]{domain.EscapeMarkup()}[/] [grey]// Hacker Wizard[/]"))
        {
            Border = BoxBorder.Rounded,
            BorderStyle = new Style(Color.Green),
            Header = new PanelHeader("[bold]🚀 Live Scan[/]")
        };

        // Stages table
        var table = new Table { Border = TableBorder.None };
        table.AddColumn(new TableColumn("Stage"));
        table.AddColumn(new TableColumn("Status"));
        table.AddColumn(new TableColumn("Progress"));
        foreach (var s in stages)
        {
            var status = s.Status switch
            {
                StageStatus.Pending => "[grey]pending[/]",
                StageStatus.Running => $"[yellow]{spinner} running[/]",
                StageStatus.Done => "[green]✓ done[/]",
                StageStatus.Skipped => "[blue]⤼ skipped[/]",
                _ => ""
            };
            var blocks = (int)Math.Round(Math.Clamp(s.Progress, 0, 100) / 10.0);
            var bar = new string('█', blocks) + new string('░', 10 - blocks);
            var color = s.Status == StageStatus.Done ? "green" : s.Status == StageStatus.Running ? "yellow" : s.Status == StageStatus.Skipped ? "blue" : "grey";
            table.AddRow(new Markup(s.Title), new Markup(status), new Markup($"[{color}]{bar}[/] {s.Progress:0}%"));
        }
        var stagePanel = new Panel(table)
        {
            Border = BoxBorder.Heavy,
            Header = new PanelHeader("[bold]🧪 Stages[/]")
        };

        // Log window
        var logText = logs.Length == 0 ? "[dim]waiting for output…[/]" : string.Join("\n", logs.TakeLast(18).Select(l => l));
        var logPanel = new Panel(new Markup(logText))
        {
            Border = BoxBorder.Ascii,
            Header = new PanelHeader("[bold]📟 Console[/]")
        };

        // Optional matrix footer
        var footer = new Panel(new Markup(matrix ? MakeMatrixLine(rnd) : "")) { Border = BoxBorder.None };

        var layout = new Layout("root").SplitRows(
            new Layout("top").Size(3).Update(header),
            new Layout("middle").SplitColumns(
                new Layout("left").Update(stagePanel),
                new Layout("right").Update(logPanel)
            ),
            new Layout("bottom").Size(1).Update(footer)
        );

        return layout;
    }

    private static string MakeMatrixLine(Random rnd)
    {
        const string chars = "01░▓█ΛΔ≡#%^*+[]{}<>";
        var len = 64;
        var s = new char[len];
        for (int i = 0; i < len; i++) s[i] = chars[rnd.Next(chars.Length)];
        return $"[green]{new string(s)}[/]";
    }

    public static void FinalSummary(DomainHealthCheck hc, string domain)
    {
        var grid = new Grid().AddColumn().AddColumn();
        grid.AddRow(new Markup("[bold]Domain[/]"), new Markup(domain.EscapeMarkup()))
            .AddRow(new Markup("[bold]DNSSEC[/]"), new Markup(hc.DnsSecAnalysis?.ChainValid == true ? "[green]Valid[/]" : "[red]No/Invalid[/]"))
            .AddRow(new Markup("[bold]Registrar[/]"), new Markup(hc.WhoisAnalysis?.Registrar?.EscapeMarkup() ?? "—"));
        var p = new Panel(grid) { Header = new PanelHeader("[bold]Scan Complete[/]"), Border = BoxBorder.Heavy };
        AnsiConsole.Write(p);
        AnsiConsole.WriteLine();
    }

    public static Panel PostureBars(MailPolicyScore s)
    {
        var bars = new BarChart().Width(36);
        bars.AddItem("SPF", s.SpfCoverage, s.SpfCoverage >= 85 ? Color.Green : s.SpfCoverage >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("DKIM", s.DkimSelectors, s.DkimSelectors >= 85 ? Color.Green : s.DkimSelectors >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("DMARC", s.DmarcStrength, s.DmarcStrength >= 85 ? Color.Green : s.DmarcStrength >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("TLS", s.TransportTlsPosture, s.TransportTlsPosture >= 85 ? Color.Green : s.TransportTlsPosture >= 60 ? Color.Yellow : Color.Red);
        return new Panel(bars) { Header = new PanelHeader("[bold]Email Posture[/]"), Border = BoxBorder.Rounded };
    }
}

// Helpers
internal static partial class Ui
{
    public static void RenderCheckSummariesPanel(DomainHealthCheck hc, bool includeActiveMailProbes, ScanMode mode)
    {
        var table = new Table();
        table.Border = TableBorder.Rounded;
        table.AddColumn(new TableColumn("Area").LeftAligned());
        table.AddColumn(new TableColumn("Check").LeftAligned());
        table.AddColumn(new TableColumn("Status").LeftAligned());
        table.AddColumn(new TableColumn("Summary").LeftAligned());

        // DNS core
        try { var v = Converters.Convert(hc.NSAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.SOAAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.DnsSecAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.WildcardDnsAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.ZoneTransferAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.DnsTtlAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }

        // Mail core
        try { var v = Converters.Convert(hc.MXAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.SpfAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.DmarcAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.BimiAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.MTASTSAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        try { var v = Converters.Convert(hc.TLSRPTAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }

        if (includeActiveMailProbes)
        {
            try { var v = Converters.Convert(hc.StartTlsAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.SmtpTlsAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.ImapTlsAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.Pop3TlsAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.SmtpBannerAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.SmtpAuthAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.OpenRelayAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        }

        // Web (not in Quick mode)
        if (mode != ScanMode.Quick)
        {
            try { var v = Converters.Convert(hc.HttpAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.CertificateAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.DaneAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        }

        // Reputation (Full mode)
        if (mode == ScanMode.Full)
        {
            try { var v = Converters.Convert(hc.WhoisAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.RdapAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.RpkiAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.DNSBLAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
            try { var v = Converters.Convert(hc.ThreatIntelAnalysis); table.AddRow(v.Area.ToString(), v.Check.ToString(), v.Status, v.Summary); } catch { }
        }

        // If no rows gathered, skip rendering
        if (table.Rows.Count == 0) return;

        var panel = new Panel(table) { Header = new PanelHeader("[bold]Check Summaries[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
    // Map HealthCheckType to a user-friendly label for progress lines
    internal static string FriendlyOpName(HealthCheckType ht) => ht switch
    {
        HealthCheckType.MTASTS => "MTA-STS",
        HealthCheckType.TLSRPT => "TLS-RPT",
        HealthCheckType.REVERSEDNS => "Reverse DNS",
        HealthCheckType.FCRDNS => "FCrDNS",
        HealthCheckType.PORTAVAILABILITY => "Port Availability",
        HealthCheckType.PORTSCAN => "Port Scan",
        HealthCheckType.DANGLINGCNAME => "Dangling CNAME",
        HealthCheckType.WILDCARDDNS => "Wildcard DNS",
        HealthCheckType.DNSTUNNELING => "DNS Tunneling",
        HealthCheckType.IPNEIGHBOR => "IP Neighbors",
        HealthCheckType.SECURITYTXT => "security.txt",
        HealthCheckType.MESSAGEHEADER => "Message Header",
        HealthCheckType.SMTPBANNER => "SMTP Banner",
        HealthCheckType.SMTPAUTH => "SMTP AUTH",
        HealthCheckType.SMTPTLS => "SMTP TLS",
        HealthCheckType.IMAPTLS => "IMAP TLS",
        HealthCheckType.POP3TLS => "POP3 TLS",
        HealthCheckType.OPENRESOLVER => "Open Resolver",
        HealthCheckType.ZONETRANSFER => "Zone Transfer",
        HealthCheckType.FLATTENINGSERVICE => "Flattening Service",
        HealthCheckType.DNSBL => "DNS Blacklists",
        HealthCheckType.CERT => "TLS Certificate",
        _ => ht.ToString()
    };

    internal static string FriendlyStageName(int idx) => idx switch
    {
        0 => "DNS",
        1 => "Mail",
        2 => "Web",
        3 => "Reputation",
        _ => $"Stage{idx}"
    };
}

internal static partial class Ui
{
    public static void RenderPersonaLogPanel(string title, IEnumerable<string> lines)
    {
        var clean = lines.Select(l => string.Join(' ', (l ?? string.Empty).Split(new[] {"\r\n", "\n", "\r"}, StringSplitOptions.RemoveEmptyEntries)).Trim());
        var content = new Markup(string.Join("\n", clean));
        var panel = new Panel(content) { Header = new PanelHeader($"[bold]{title}[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static IEnumerable<RecommendationView> FilterRecommendationsForStage(IEnumerable<RecommendationView> views, int stage)
    {
        string[] tokens = stage switch
        {
            0 => new[] { "NS", "SOA", "DNSSEC", "WILDCARD", "OPENRESOLVER", "AXFR", "TTL", "RDNS", "REVERSE", "CAA" },
            1 => new[] { "SPF", "DKIM", "DMARC", "BIMI", "MTASTS", "TLSRPT", "STARTTLS", "SMTP", "IMAPTLS", "POP3TLS", "OPENRELAY", "ARC" },
            2 => new[] { "HTTP", "CERT", "DANE", "HPKP", "SECURITYTXT", "DIRECTORY", "CSP", "HSTS" },
            _ => new[] { "WHOIS", "RDAP", "RPKI", "DNSBL", "THREAT", "IPNEIGHBOR" }
        };
        var domains = stage switch
        {
            0 => new[] { RecommendationDomain.Infrastructure, RecommendationDomain.Dnssec },
            1 => new[] { RecommendationDomain.EmailAuth, RecommendationDomain.Tls },
            2 => new[] { RecommendationDomain.Http, RecommendationDomain.Tls },
            _ => new[] { RecommendationDomain.ThreatIntel, RecommendationDomain.Infrastructure }
        };
        return views.Where(v =>
            (!string.IsNullOrWhiteSpace(v.Category) && tokens.Any(t => v.Category.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0)) ||
            domains.Contains(v.Advice.Domain))
            .OrderByDescending(v => v.MaxSeverity)
            .ThenBy(v => v.Category)
            .ThenBy(v => v.Code);
    }

    public static void RenderRecommendationsPanel(string title, IEnumerable<RecommendationView> views)
    {
        var rows = new List<IRenderable>();
        foreach (var v in views)
        {
            var icon = v.MaxSeverity switch
            {
                AssessmentSeverity.Error => "[red]❌[/]",
                AssessmentSeverity.Warning => "[yellow]⚠️[/]",
                _ => "[blue]ℹ️[/]"
            };
            var targets = v.Targets != null && v.Targets.Count > 0 ? $" [dim]({string.Join(", ", v.Targets).EscapeMarkup()})[/]" : string.Empty;
            rows.Add(new Markup($"{icon} {v.Advice.Title.EscapeMarkup()}{targets}"));
        }
        var panel = new Panel(new Rows(rows)) { Header = new PanelHeader($"[bold]{title}[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
    public static void RenderStageFindings(DomainHealthCheck hc, int stageIndex)
    {
        switch (stageIndex)
        {
            case 0: // DNS
            {
                var rows = new List<IRenderable>
                {
                    new Markup($"DNSSEC: {(hc.DnsSecAnalysis?.ChainValid == true ? "[green]valid[/]" : "[red]no/invalid[/]")}"),
                    new Markup($"NS count: {hc.NSAnalysis?.NsRecords?.Count ?? 0}"),
                    new Markup($"Wildcard: {(hc.WildcardDnsAnalysis?.CatchAll == true ? "[red]yes[/]" : "[green]no[/]")}"),
                    new Markup($"Open resolver(s): {hc.OpenResolverAnalysis?.ServerResults?.Count(kv => kv.Value) ?? 0}"),
                    new Markup($"AXFR open: {hc.ZoneTransferAnalysis?.ServerResults?.Count(kv => kv.Value) ?? 0}")
                };
                AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader("[bold]🧭 DNS Findings[/]"), Border = BoxBorder.Rounded });
                AnsiConsole.WriteLine();
                break;
            }
            case 1: // Mail
            {
                var rows = new List<IRenderable>
                {
                    new Markup($"SPF: {(hc.SpfAnalysis?.SpfRecordExists == true ? "[green]present[/]" : "[red]missing[/]")}"),
                    new Markup($"DKIM selectors: {hc.DKIMAnalysis?.AnalysisResults?.Count ?? 0}"),
                    new Markup($"DMARC: {(hc.DmarcAnalysis?.DmarcRecordExists == true ? (hc.DmarcAnalysis.PolicyShort ?? hc.DmarcAnalysis.Policy).EscapeMarkup() : "[red]missing[/]")}"),
                    new Markup($"MTA-STS: {(hc.MTASTSAnalysis?.PolicyPresent == true ? "present" : "missing")}"),
                    new Markup($"TLS-RPT: {(hc.TLSRPTAnalysis?.TlsRptRecord != null ? "present" : "missing")}")
                };
                AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader("[bold]📧 Mail Findings[/]"), Border = BoxBorder.Rounded });
                AnsiConsole.WriteLine();
                break;
            }
            case 2: // Web
            {
                var rows = new List<IRenderable>
                {
                    new Markup($"HTTP: {(hc.HttpAnalysis?.IsReachable == true ? "[green]ok[/]" : "[red]no[/]")}"),
                    new Markup($"HTTPS: {(hc.CertificateAnalysis?.IsReachable == true ? "[green]ok[/]" : "[red]no[/]")}"),
                    new Markup($"HSTS: {(hc.HttpAnalysis?.HstsPresent == true ? "present" : "absent")}"),
                    new Markup($"HTTP/2: {(hc.CertificateAnalysis?.Http2Supported == true ? "yes" : "no")}, HTTP/3: {(hc.CertificateAnalysis?.Http3Supported == true ? "yes" : "no")}"),
                };
                AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader("[bold]🌐 Web Findings[/]"), Border = BoxBorder.Rounded });
                AnsiConsole.WriteLine();
                break;
            }
            case 3: // Reputation
            {
                var rows = new List<IRenderable>
                {
                    new Markup($"Registrar: {(hc.WhoisAnalysis?.Registrar?.EscapeMarkup() ?? "—")}"),
                    new Markup($"RDAP RegistrarId: {(hc.RdapAnalysis?.RegistrarId?.EscapeMarkup() ?? "—")}"),
                    new Markup($"RPKI all valid: {hc.RpkiAnalysis?.AllValid}"),
                    new Markup($"DNSBL: {(hc.DNSBLAnalysis?.Blacklisted ?? 0)} listed / {(hc.DNSBLAnalysis?.RecordChecked ?? 0)} checked")
                };
                AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader("[bold]🛡 Reputation Findings[/]"), Border = BoxBorder.Rounded });
                AnsiConsole.WriteLine();
                break;
            }
        }
    }
    public static void RenderPosturePanels(DomainHealthCheck hc)
    {
        var emailBars = Fx.PostureBars(new Fx.MailPolicyScore
        {
            SpfCoverage = hc.SpfAnalysis?.SpfRecordExists == true ? 90 : 0,
            DkimSelectors = hc.DKIMAnalysis?.AnalysisResults?.Count(k => k.Value.ValidPublicKey && k.Value.ValidKeyType && k.Value.ValidFlags) * 25 ?? 0,
            DmarcStrength = hc.DmarcAnalysis?.PolicyShort switch { "reject" => 100, "quarantine" => 80, "none" => 20, _ => 0 },
            TransportTlsPosture =
                (hc.SmtpTlsAnalysis?.ServerResults?.Any(kv => kv.Value.CertificateValid) == true ? 40 : 0) +
                (hc.ImapTlsAnalysis?.ServerResults?.Any(kv => kv.Value.CertificateValid) == true ? 30 : 0) +
                (hc.Pop3TlsAnalysis?.ServerResults?.Any(kv => kv.Value.CertificateValid) == true ? 30 : 0)
        });

        var dnsPanel = new Panel(new Rows(
            new Markup($"DNSSEC: {(hc.DnsSecAnalysis?.ChainValid == true ? "[green]OK[/]" : "[red]NO[/]")}"),
            new Markup($"Wildcard: {(hc.WildcardDnsAnalysis?.CatchAll == true ? "[red]YES[/]" : "[green]NO[/]")}"),
            new Markup($"Open Resolver: {(hc.OpenResolverAnalysis?.ServerResults?.Any(kv => kv.Value) == true ? "[red]YES[/]" : "[green]NO[/]")}"),
            new Markup($"AXFR: {(hc.ZoneTransferAnalysis?.ServerResults?.Any(kv => kv.Value) == true ? "[red]OPEN[/]" : "[green]CLOSED[/]")}")
        )) { Header = new PanelHeader("[bold]DNS Posture[/]"), Border = BoxBorder.Rounded };

        var httpPanel = new Panel(new Rows(
            new Markup($"HTTP: {(hc.HttpAnalysis?.IsReachable == true ? "[green]OK[/]" : "[red]NO[/]")}"),
            new Markup($"HTTPS: {(hc.CertificateAnalysis?.IsReachable == true ? "[green]OK[/]" : "[red]NO[/]")}"),
            new Markup($"H2/H3: {(hc.CertificateAnalysis?.Http2Supported == true ? "[green]H2[/]" : "[red]H2[/]")}/{(hc.CertificateAnalysis?.Http3Supported == true ? "[green]H3[/]" : "[red]H3[/]")}")
        )) { Header = new PanelHeader("[bold]Web Posture[/]"), Border = BoxBorder.Rounded };

        var grid = new Grid().AddColumn().AddColumn();
        grid.AddRow(emailBars, dnsPanel).AddRow(httpPanel, new Panel(" ") { Border = BoxBorder.None });
        AnsiConsole.Write(grid);
        AnsiConsole.WriteLine();
    }

    public static void RenderDnsTree(DomainHealthCheck hc, bool advanced)
    {
        var root = new Tree("[bold]DNS[/]");
        var ns = root.AddNode("[white]NS[/]");
        foreach (var n in hc.NSAnalysis?.NsRecords ?? Enumerable.Empty<string>()) ns.AddNode($"[green]{n.EscapeMarkup()}[/]");
        var soa = root.AddNode("[white]SOA[/]");
        if (hc.SOAAnalysis?.RecordExists == true)
        {
            soa.AddNode($"MNAME: [yellow]{hc.SOAAnalysis.PrimaryNameServer?.EscapeMarkup()}[/]");
            soa.AddNode($"RNAME: [yellow]{hc.SOAAnalysis.ResponsibleMailbox?.EscapeMarkup()}[/]");
            soa.AddNode($"Serial: [yellow]{hc.SOAAnalysis.SerialNumber}[/]");
        }
        var mx = root.AddNode("[white]MX[/]");
        foreach (var rec in hc.MXAnalysis?.MxRecords ?? Enumerable.Empty<string>()) mx.AddNode(rec.EscapeMarkup());
        AnsiConsole.Write(root);
        AnsiConsole.WriteLine();

        var ttlAll = (hc.DnsTtlAnalysis?.ATtls ?? Array.Empty<int>())
            .Concat(hc.DnsTtlAnalysis?.AaaaTtls ?? Array.Empty<int>())
            .Concat(hc.DnsTtlAnalysis?.MxTtls ?? Array.Empty<int>())
            .Concat(hc.DnsTtlAnalysis?.NsTtls ?? Array.Empty<int>())
            .Where(x => x > 0).ToArray();
        var panel = new Panel(new Rows(
            new Markup($"DNSSEC: {(hc.DnsSecAnalysis?.ChainValid == true ? "[green]OK[/]" : "[red]NO[/]")}"),
            new Markup($"Wildcard: {(hc.WildcardDnsAnalysis?.CatchAll == true ? "[red]YES[/]" : "[green]NO[/]")}"),
            new Markup($"Open Resolver: {(hc.OpenResolverAnalysis?.ServerResults?.Any(kv => kv.Value) == true ? "[red]YES[/]" : "[green]NO[/]")}"),
            new Markup($"AXFR: {(hc.ZoneTransferAnalysis?.ServerResults?.Any(kv => kv.Value) == true ? "[red]OPEN[/]" : "[green]CLOSED[/]")}"),
            new Markup($"TTL(min): {(ttlAll.Length>0? TimeSpan.FromSeconds(ttlAll.Min()).ToString():"—")}"),
            new Markup($"TTL(max): {(ttlAll.Length>0? TimeSpan.FromSeconds(ttlAll.Max()).ToString():"—")}")
        )) { Header = new PanelHeader("[bold]DNS Posture[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();

        if (advanced)
        {
            foreach (var w in hc.DnsTtlAnalysis?.Warnings ?? Array.Empty<string>())
                AnsiConsole.MarkupLine($"[yellow]- {w.EscapeMarkup()}[/]");
            foreach (var m in hc.DnsSecAnalysis?.MismatchSummary ?? Array.Empty<string>())
                AnsiConsole.MarkupLine($"[yellow]- {m.EscapeMarkup()}[/]");
        }
    }

    public static void RenderMailTree(DomainHealthCheck hc, bool advanced)
    {
        var root = new Tree("[bold]Mail[/]");
        var spf = root.AddNode("[white]SPF[/]");
        spf.AddNode((hc.SpfAnalysis?.SpfRecord ?? "—").EscapeMarkup());
        if (advanced)
        {
            spf.AddNode($"Lookups: {hc.SpfAnalysis?.DnsLookupsCount} / Exceeds10: {hc.SpfAnalysis?.ExceedsDnsLookups}");
            var providers = hc.SpfAnalysis?.SpfPartAnalyses?
                .Where(p => !string.IsNullOrWhiteSpace(p.Provider))
                .Select(p => p.Provider!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray() ?? Array.Empty<string>();
            if (providers.Length > 0)
                spf.AddNode($"Providers: {string.Join(", ", providers).EscapeMarkup()}");
        }
        var dmarc = root.AddNode("[white]DMARC[/]");
        dmarc.AddNode((hc.DmarcAnalysis?.DmarcRecord ?? "—").EscapeMarkup());
        if (advanced)
        {
            dmarc.AddNode($"Policy: {hc.DmarcAnalysis?.Policy}");
            dmarc.AddNode($"Valid: {hc.DmarcAnalysis?.IsPolicyValid}");
        }
        var dkim = root.AddNode("[white]DKIM[/]");
        var dkimResults = hc.DKIMAnalysis?.AnalysisResults ?? new Dictionary<string, DkimRecordAnalysis>();
        // Compact coverage/providers hint
        if (dkimResults.Count > 0)
        {
            var selList = dkimResults.Keys.ToArray();
            var providers = MapDkimProviders(selList).ToArray();
            dkim.AddNode($"Selectors: {selList.Length}; Providers: {(providers.Length>0 ? string.Join(", ", providers) : "—")}");
        }
        foreach (var kv in dkimResults)
        {
            var sel = dkim.AddNode($"[green]{kv.Key}[/]");
            sel.AddNode($"KeyLength: {kv.Value.KeyLength}");
            sel.AddNode($"Valid: {kv.Value.ValidPublicKey && kv.Value.ValidKeyType && kv.Value.ValidFlags}");
        }
        var mtasts = root.AddNode("[white]MTA-STS[/]");
        mtasts.AddNode($"Present: {hc.MTASTSAnalysis?.PolicyPresent}");
        mtasts.AddNode($"Mode: {hc.MTASTSAnalysis?.Mode}");
        var tlsrpt = root.AddNode("[white]TLS-RPT[/]");
        tlsrpt.AddNode((hc.TLSRPTAnalysis?.TlsRptRecord ?? "—").EscapeMarkup());
        AnsiConsole.Write(root);
        AnsiConsole.WriteLine();
        if (advanced)
        {
            RenderTlsResults("STARTTLS", hc.StartTlsAnalysis?.ServerResults?.Select(kv => ($"{kv.Key}", ok: kv.Value)));
            RenderTlsResults("SMTP TLS", hc.SmtpTlsAnalysis?.ServerResults?.Select(kv => ($"{kv.Key}", ok: kv.Value.CertificateValid)));
            RenderTlsResults("IMAP TLS", hc.ImapTlsAnalysis?.ServerResults?.Select(kv => ($"{kv.Key}", ok: kv.Value.CertificateValid)));
            RenderTlsResults("POP3 TLS", hc.Pop3TlsAnalysis?.ServerResults?.Select(kv => ($"{kv.Key}", ok: kv.Value.CertificateValid)));
        }
    }

    private static readonly Dictionary<string, string> DkimSelectorProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft 365
        ["selector1"] = "Microsoft 365",
        ["selector2"] = "Microsoft 365",
        // Google Workspace
        ["google"] = "Google Workspace",
        // SendGrid
        ["s1"] = "SendGrid",
        ["s2"] = "SendGrid",
        // SparkPost
        ["scph"] = "SparkPost",
        // Zoho
        ["zoho"] = "Zoho",
        ["zoho2"] = "Zoho",
        // Mailgun
        ["mg"] = "Mailgun",
        ["mailgun"] = "Mailgun",
        // Fastmail
        ["fm1"] = "Fastmail",
        ["fm2"] = "Fastmail",
        ["fm3"] = "Fastmail",
        // cPanel
        ["default"] = "cPanel",
        ["mail"] = "cPanel",
        // Campaign Monitor
        ["cm"] = "Campaign Monitor",
        ["cm1"] = "Campaign Monitor",
        ["cm2"] = "Campaign Monitor",
        // HubSpot
        ["hs1"] = "HubSpot",
        ["hs2"] = "HubSpot",
        // ProtonMail
        ["protonmail"] = "ProtonMail",
        ["protonmail2"] = "ProtonMail",
        ["pm"] = "ProtonMail"
    };

    private static IEnumerable<string> MapDkimProviders(IEnumerable<string> selectors)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in selectors)
        {
            if (string.IsNullOrWhiteSpace(s)) continue;
            if (DkimSelectorProviders.TryGetValue(s, out var provider))
            {
                if (seen.Add(provider)) yield return provider;
            }
        }
    }

    private static void RenderTlsResults(string title, IEnumerable<(string host, bool ok)>? items)
    {
        if (items == null) return;
        var panel = new Panel(new Rows(items.Select(i => new Markup($"{i.host.EscapeMarkup()}: {(i.ok ? "[green]OK[/]" : "[red]NO[/]")}")).ToArray()))
        { Header = new PanelHeader($"[bold]{title}[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static void RenderWebTree(DomainHealthCheck hc, bool advanced)
    {
        var root = new Tree("[bold]Web[/]");
        var http = root.AddNode("[white]HTTP[/]");
        http.AddNode($"Reachable: {hc.HttpAnalysis?.IsReachable}");
        http.AddNode($"Status: {hc.HttpAnalysis?.StatusCode}");
        http.AddNode($"HSTS: {hc.HttpAnalysis?.HstsPresent}");
        if (hc.HttpAnalysis?.MissingSecurityHeaders?.Count > 0)
            http.AddNode($"Missing: {string.Join(", ", hc.HttpAnalysis.MissingSecurityHeaders).EscapeMarkup()}");
        var https = root.AddNode("[white]HTTPS/TLS[/]");
        https.AddNode($"Reachable: {hc.CertificateAnalysis?.IsReachable}");
        https.AddNode($"Subject: {hc.CertificateAnalysis?.Certificate?.Subject?.EscapeMarkup() ?? "—"}");
        https.AddNode($"Issuer: {hc.CertificateAnalysis?.Certificate?.Issuer?.EscapeMarkup() ?? "—"}");
        https.AddNode($"NotAfter: {hc.CertificateAnalysis?.Certificate?.NotAfter:u}");
        https.AddNode($"H2/H3: {hc.CertificateAnalysis?.Http2Supported}/{hc.CertificateAnalysis?.Http3Supported}");
        var dane = root.AddNode("[white]DANE[/]");
        dane.AddNode($"Records: {hc.DaneAnalysis?.NumberOfRecords}");
        AnsiConsole.Write(root);
        AnsiConsole.WriteLine();
    }

    public static void RenderReputationTree(DomainHealthCheck hc, bool advanced)
    {
        var root = new Tree("[bold]Reputation/Registry[/]");
        var whois = root.AddNode("[white]WHOIS[/]");
        whois.AddNode($"Registrar: {hc.WhoisAnalysis?.Registrar?.EscapeMarkup() ?? "—"}");
        whois.AddNode($"Expiry: {hc.WhoisAnalysis?.ExpiryDate ?? "—"}");
        var rdap = root.AddNode("[white]RDAP[/]");
        rdap.AddNode($"RegistrarId: {hc.RdapAnalysis?.RegistrarId ?? "—"}");
        var rpki = root.AddNode("[white]RPKI[/]");
        rpki.AddNode($"All Valid: {hc.RpkiAnalysis?.AllValid}");
        var dnsbl = root.AddNode("[white]DNSBL[/]");
        var blacklisted = hc.DNSBLAnalysis?.AllResults?.Where(r => r.IsBlackListed).Select(r => r.BlackList).Distinct().OrderBy(s => s) ?? Enumerable.Empty<string>();
        foreach (var bl in blacklisted) dnsbl.AddNode($"[red]{bl.EscapeMarkup()}[/]");
        AnsiConsole.Write(root);
        AnsiConsole.WriteLine();
    }
}
