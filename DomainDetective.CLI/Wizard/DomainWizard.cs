using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using DomainDetective;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace DomainDetective.CLI.Wizard;

public enum ScanMode { Default, Quick, Full }

public sealed class WizardOptions
{
    public required string Domain { get; init; }
    public ScanMode Mode { get; init; } = ScanMode.Default; // quick|default|full
    public string Output { get; init; } = "console"; // console|json|html
    public string? Out { get; init; }
    public bool Matrix { get; init; } = false;
    public bool ActiveMailProbes { get; init; } = false;
    public string Details { get; init; } = "standard"; // summary|standard|advanced
    public HealthCheckType[]? Checks { get; init; }
    public string Persona { get; init; } = "business"; // business|funny|geek|noir|pirate
    public bool PersonaLive { get; init; } = true;
    public bool PersonaVerbose { get; init; } = false;
    public bool ShowTitle { get; init; } = true; // suppress duplicate header when caller already showed welcome
    public bool DisableLive { get; init; } = false; // force simple streaming UI
}

public sealed class DomainWizard
{
    public WizardOptions Options { get; }
    public DomainWizard(WizardOptions options) => Options = options;

    public async Task<DomainHealthCheck> RunAsync(CancellationToken ct = default)
    {
        if (Options.Output == "console" && Options.ShowTitle)
        {
            Fx.TitleScreen(Options.Domain, Options.Matrix, Options.Persona);
        }

        // Wire internal logger; we'll map progress to Spectre tasks
        var ilog = new InternalLogger();
        var hc = new DomainHealthCheck(internalLogger: ilog) { Progress = false, Verbose = false };

        HealthCheckType[] dnsChecks;
        List<HealthCheckType> mailChecksList;
        HealthCheckType[] webChecks;
        HealthCheckType[] repChecks;

        if (Options.Checks != null && Options.Checks.Length > 0)
        {
            var set = new HashSet<HealthCheckType>(Options.Checks);
            dnsChecks = new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL }.Where(set.Contains).ToArray();
            var mailBase = new[] { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT };
            mailChecksList = mailBase.Where(set.Contains).ToList();
            // If user selected any active probes include them; otherwise honor ActiveMailProbes flag
            var probes = new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY };
            var selectedProbes = probes.Where(set.Contains).ToArray();
            if (selectedProbes.Length > 0)
                mailChecksList.AddRange(selectedProbes);
            else if (Options.ActiveMailProbes)
                mailChecksList.AddRange(probes);
            webChecks = new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE }.Where(set.Contains).ToArray();
            repChecks = new[] { HealthCheckType.DNSBL, HealthCheckType.RDAP, HealthCheckType.RPKI }.Where(set.Contains).ToArray();
        }
        else
        {
            dnsChecks = new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL };
            mailChecksList = new List<HealthCheckType> { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT };
            if (Options.ActiveMailProbes)
            {
                mailChecksList.AddRange(new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY });
            }
            webChecks = new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE };
            repChecks = new[] { HealthCheckType.DNSBL, HealthCheckType.RDAP, HealthCheckType.RPKI };
        }

        var stages = new List<(string Title, HealthCheckType[] Types, bool Enabled)>
        {
            ("🧭 DNS", dnsChecks, dnsChecks.Length > 0),
            ("📧 Mail", mailChecksList.ToArray(), mailChecksList.Count > 0),
            ("🌐 Web", webChecks, webChecks.Length > 0 && Options.Mode != ScanMode.Quick),
            ("🛡 Reputation", repChecks, repChecks.Length > 0 && Options.Mode == ScanMode.Full)
        };

        var typeToStage = new Dictionary<HealthCheckType, int>();
        for (int i = 0; i < stages.Count; i++)
            if (stages[i].Enabled)
                foreach (var t in stages[i].Types) typeToStage[t] = i;

        ProgressTask[] stageTasks = Array.Empty<ProgressTask>();
        var activeStages = stages.Select((s, idx) => (s, idx)).Where(t => t.s.Enabled).ToArray();
        var stageIndexMap = activeStages.Select((t, activeIdx) => (t.idx, activeIdx)).ToDictionary(x => x.idx, x => x.activeIdx);
        // Persona live narration buffer per stage
        var stageLogs = new Dictionary<int, List<string>>();
        var stageLastLine = new Dictionary<int, string>();
        PersonaKind personaKind = Options.Persona?.ToLowerInvariant() switch {
            "funny" => PersonaKind.Funny,
            "geek"  => PersonaKind.Geek,
            "noir"  => PersonaKind.Noir,
            "pirate"=> PersonaKind.Pirate,
            _ => PersonaKind.Business
        };
        int currentStageIdx = -1;
        void AppendPersonaLine(AssessmentSeverity sev, string? code, string message)
        {
            if (!Options.PersonaLive) return;
            var a = new Assessment {
                Severity = sev,
                Category = !string.IsNullOrWhiteSpace(code) ? (code!.Split('.')[0]) : "Log",
                Code = code,
                Message = message
            };
            var line = PersonaFormatter.Format(a, personaKind);
            if (!stageLogs.TryGetValue(currentStageIdx, out var list)) { list = new List<string>(); stageLogs[currentStageIdx] = list; }
            list.Add(line);
            if (list.Count > 50) list.RemoveAt(0);
            stageLastLine[currentStageIdx] = line;
        }

        ilog.OnProgressMessage += (_, e) =>
        {
            if (stageTasks.Length == 0) return;
            if (!Enum.TryParse<HealthCheckType>(e.ProgressCurrentOperation ?? string.Empty, ignoreCase: true, out var ht)) return;
            if (!typeToStage.TryGetValue(ht, out var fullIdx)) return;
            if (!stageIndexMap.TryGetValue(fullIdx, out var idx)) return;
            var task = stageTasks[idx];
            if (!task.IsFinished)
            {
                var desc = $"{stages[idx].Title} [dim]{ht}[/]";
                if (Options.PersonaLive && stageLastLine.TryGetValue(idx, out var last))
                {
                    // Keep the inline narration short to avoid flicker
                    var shortLast = last.Length > 80 ? last.Substring(0, 77) + "…" : last;
                    desc = $"{desc} [grey]|[/] {shortLast}";
                }
                task.Description = desc;
                task.Value = Math.Clamp(e.ProgressPercentage ?? 0, 0, 100);
            }
        };

        if (Options.PersonaLive)
        {
            ilog.OnWarningMessage += (_, e) => AppendPersonaLine(AssessmentSeverity.Warning, e.Code, e.FullMessage);
            // Show information-level narration even without verbose to avoid a "silent" progress experience
            ilog.OnInformationMessage += (_, e) => AppendPersonaLine(AssessmentSeverity.Info, e.Code, e.FullMessage);
            if (Options.PersonaVerbose)
            {
                ilog.OnVerboseMessage += (_, e) => AppendPersonaLine(AssessmentSeverity.Info, e.Code, e.FullMessage);
            }
        }

        // Live layout: log panel on top, progress table at the bottom
        if (Options.Output == "console")
        {
            var canLive = AnsiConsole.Profile.Capabilities.Ansi && AnsiConsole.Profile.Capabilities.Interactive && !Options.DisableLive;
            var liveLines = new List<string>();
            var progressLineNeedsRedraw = false;
            var termLock = new object();
            string ComposeProgressLine(Dictionary<int,int> progress, Dictionary<int,string> ops)
            {
                var parts = new List<string>();
                string[] names = new[] { "DNS", "Mail", "Web", "Rep" };
                for (int i = 0; i < stages.Count && i < names.Length; i++)
                {
                    if (!stages[i].Enabled) continue;
                    if (!progress.TryGetValue(i, out var p)) continue;
                    ops.TryGetValue(i, out var op);
                    var now = string.IsNullOrWhiteSpace(op) ? string.Empty : $" {op}";
                    parts.Add($"{names[i]} {p,3}%{now}");
                }
                return parts.Count > 0 ? $"Status: {string.Join(" | ", parts)}" : string.Empty;
            }

            void AppendGlobal(string line) {
                // Normalize multi-line messages into a single, concise line
                var compact = string.Join(' ', (line ?? string.Empty).Split(new[] {"\r\n", "\n", "\r"}, StringSplitOptions.RemoveEmptyEntries)).Trim();
                if (compact.Length > 220) compact = compact.Substring(0, 217) + "…";
                liveLines.Add(compact);
                if (liveLines.Count > 400) liveLines.RemoveAt(0);
                if (!canLive)
                {
                    // In simple UI, print log on a fresh line and re-draw status pinned line
                    lock (termLock)
                    {
                        Console.Write("\r\x1b[2K");
                        AnsiConsole.MarkupLine(compact);
                        progressLineNeedsRedraw = true;
                    }
                }
            }

            // Hook global appends: for simple UI prefer plain messages, persona only styles in live mode
            ilog.OnWarningMessage += (_, e) =>
            {
                var msg = Options.DisableLive ? $"⚠️ {e.FullMessage}" : PersonaFormatter.Format(new Assessment { Severity = AssessmentSeverity.Warning, Code = e.Code, Message = e.FullMessage }, personaKind);
                AppendGlobal(msg);
            };
            ilog.OnInformationMessage += (_, e) =>
            {
                var msg = Options.DisableLive ? $"ℹ️ {e.FullMessage}" : PersonaFormatter.Format(new Assessment { Severity = AssessmentSeverity.Info, Code = e.Code, Message = e.FullMessage }, personaKind);
                AppendGlobal(msg);
            };
            if (Options.PersonaVerbose)
            {
                ilog.OnVerboseMessage += (_, e) =>
                {
                    var msg = Options.DisableLive ? $"· {e.FullMessage}" : PersonaFormatter.Format(new Assessment { Severity = AssessmentSeverity.Info, Code = e.Code, Message = e.FullMessage }, personaKind);
                    AppendGlobal(msg);
                };
            }

            var stageProgress = new Dictionary<int, int>();
            var stageOp = new Dictionary<int, string>();
            for (int i = 0; i < stages.Count; i++) if (stages[i].Enabled) stageProgress[i] = 0;

            ilog.OnProgressMessage += (_, e) =>
            {
                if (!Enum.TryParse<HealthCheckType>(e.ProgressCurrentOperation ?? string.Empty, ignoreCase: true, out var ht)) return;
                if (!typeToStage.TryGetValue(ht, out var fullIdx)) return;
                if (!stageIndexMap.TryGetValue(fullIdx, out var idx)) return;
                stageProgress[idx] = Math.Clamp(e.ProgressPercentage ?? 0, 0, 100);
                stageOp[idx] = ht.ToString();
            };

            var layout = new Layout("root")
                .SplitRows(
                    new Layout("log").Ratio(3),
                    new Layout("prog").Ratio(1)
                );

            static Table BuildProgressTable(List<(string Title, HealthCheckType[] Types, bool Enabled)> stages, Dictionary<int,int> progress, Dictionary<int,string> ops)
            {
                var table = new Table();
                table.Border = TableBorder.None;
                table.AddColumn(new TableColumn("Stage").LeftAligned());
                table.AddColumn(new TableColumn("Now").LeftAligned());
                table.AddColumn(new TableColumn("Progress").LeftAligned());
                table.AddColumn(new TableColumn("% ").RightAligned());
                for (int i = 0; i < stages.Count; i++)
                {
                    if (!stages[i].Enabled) continue;
                    var p = progress.TryGetValue(i, out var v) ? v : 0;
                    var barLen = 28;
                    var filled = (int)Math.Round(p / 100.0 * barLen);
                    var bar = new string('█', Math.Clamp(filled, 0, barLen)) + new string('─', Math.Clamp(barLen - filled, 0, barLen));
                    var op = ops.TryGetValue(i, out var o) ? o : string.Empty;
                    table.AddRow(new IRenderable[]
                    {
                        new Markup(stages[i].Title),
                        new Markup(string.IsNullOrWhiteSpace(op) ? "" : op),
                        new Markup($"[green]{bar}[/]"),
                        new Markup(p.ToString("D2"))
                    });
                }
                return table;
            }

            if (!canLive)
            {
                // Fallback: stream logs while running checks sequentially and keep a pinned status line
                AnsiConsole.Write(new Panel(new Markup("[bold]Live Narration[/]\n[grey]Streaming…[/]")) { Border = BoxBorder.Rounded });
                // progress trackers
                var sProgress = new Dictionary<int, int>();
                var sOp = new Dictionary<int, string>();
                for (int i = 0; i < stages.Count; i++) if (stages[i].Enabled) sProgress[i] = 0;
                ilog.OnProgressMessage += (_, e) =>
                {
                    if (!Enum.TryParse<HealthCheckType>(e.ProgressCurrentOperation ?? string.Empty, ignoreCase: true, out var ht)) return;
                    if (!typeToStage.TryGetValue(ht, out var fullIdx)) return;
                    if (!stageIndexMap.TryGetValue(fullIdx, out var idx)) return;
                    sProgress[idx] = Math.Clamp(e.ProgressPercentage ?? 0, 0, 100);
                    sOp[idx] = ht.ToString();
                    progressLineNeedsRedraw = true;
                };

                // writer task renders pinned progress
                using var ctsProg = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var progTask = Task.Run(async () =>
                {
                    while (!ctsProg.IsCancellationRequested)
                    {
                        if (progressLineNeedsRedraw)
                        {
                            var line = ComposeProgressLine(sProgress, sOp);
                            lock (termLock)
                            {
                                Console.Write("\r\x1b[2K");
                                if (!string.IsNullOrEmpty(line)) Console.Write(line);
                                progressLineNeedsRedraw = false;
                            }
                        }
                        await Task.Delay(120, ctsProg.Token).ConfigureAwait(false);
                    }
                }, ctsProg.Token);

                try
                {
                    for (int i = 0; i < stages.Count; i++)
                    {
                        var (title, types, enabled) = stages[i];
                        if (!enabled) continue;
                        currentStageIdx = i;
                        try
                        {
                            await hc.Verify(Options.Domain, types, cancellationToken: ct);
                            if (i == 3 /* Reputation */)
                            {
                                await hc.CheckWHOIS(Options.Domain, ct);
                            }
                        }
                        catch (Exception ex)
                        {
                            AppendGlobal($"[red]{title} failed[/]: {ex.Message.EscapeMarkup()}");
                        }
                        sProgress[i] = 100;
                        progressLineNeedsRedraw = true;
                    }
                }
                finally
                {
                    // finalize progress line
                    ctsProg.Cancel();
                    try { await progTask; } catch { /* ignore */ }
                    lock (termLock)
                    {
                        Console.Write("\r\x1b[2K\n");
                    }
                }
            }
            else
            await AnsiConsole.Live(layout).StartAsync(async ctx =>
            {
                // prime UI
                layout["log"].Update(new Panel(new Markup("[grey]Waiting for activity…[/]")) { Border = BoxBorder.Rounded, Header = new PanelHeader("Live Narration"), Expand = true });
                layout["prog"].Update(new Panel(BuildProgressTable(stages, stageProgress, stageOp)) { Border = BoxBorder.Rounded, Header = new PanelHeader("Progress"), Expand = true });
                ctx.Refresh();

                // Run checks concurrently with UI refresh loop
                var done = false;
                var runner = Task.Run(async () =>
                {
                    for (int i = 0; i < stages.Count; i++)
                    {
                        var (title, types, enabled) = stages[i];
                        if (!enabled) continue;
                        currentStageIdx = i;
                        stageProgress[i] = 0;
                        try
                        {
                            await hc.Verify(Options.Domain, types, cancellationToken: ct);
                            if (i == 3 /* Reputation */)
                            {
                                await hc.CheckWHOIS(Options.Domain, ct);
                            }
                        }
                        catch (Exception ex)
                        {
                            AppendGlobal($"[red]{title} failed[/]: {ex.Message.EscapeMarkup()}");
                        }
                        stageProgress[i] = 100;
                    }
                    done = true;
                });

                // UI refresh loop
                while (!done)
                {
                    var lines = liveLines.Count > 12 ? liveLines.Skip(Math.Max(0, liveLines.Count - 12)).ToArray() : liveLines.ToArray();
                    layout["log"].Update(new Panel(new Markup(lines.Length > 0 ? string.Join("\n", lines) : "[grey]Working…[/]")) { Border = BoxBorder.Rounded, Header = new PanelHeader("Live Narration"), Expand = true });
                    layout["prog"].Update(new Panel(BuildProgressTable(stages, stageProgress, stageOp)) { Border = BoxBorder.Rounded, Header = new PanelHeader("Progress"), Expand = true });
                    ctx.Refresh();
                    await Task.Delay(250);
                }

                // final refresh
                {
                    var lines = liveLines.Count > 12 ? liveLines.Skip(Math.Max(0, liveLines.Count - 12)).ToArray() : liveLines.ToArray();
                    layout["log"].Update(new Panel(new Markup(lines.Length > 0 ? string.Join("\n", lines) : "[grey]Done.[/]")) { Border = BoxBorder.Rounded, Header = new PanelHeader("Live Narration"), Expand = true });
                    layout["prog"].Update(new Panel(BuildProgressTable(stages, stageProgress, stageOp)) { Border = BoxBorder.Rounded, Header = new PanelHeader("Progress"), Expand = true });
                    ctx.Refresh();
                }

                await runner;
            });
        }
        else
        {
            // Non-console outputs: run sequentially
            if (stages[0].Enabled) await hc.Verify(Options.Domain, stages[0].Types, cancellationToken: ct);
            if (stages[1].Enabled) await hc.Verify(Options.Domain, stages[1].Types, cancellationToken: ct);
            if (stages[2].Enabled) await hc.Verify(Options.Domain, stages[2].Types, cancellationToken: ct);
            if (stages[3].Enabled)
            {
                await hc.Verify(Options.Domain, stages[3].Types, cancellationToken: ct);
                await hc.CheckWHOIS(Options.Domain, ct);
            }
        }

        if (Options.Output == "console")
        {
            Fx.FinalSummary(hc, Options.Domain);
            var advanced = Options.Details.Equals("advanced", StringComparison.OrdinalIgnoreCase);
            var summaryOnly = Options.Details.Equals("summary", StringComparison.OrdinalIgnoreCase);

            Ui.RenderPosturePanels(hc);
            if (!summaryOnly)
            {
                Ui.RenderDnsTree(hc, advanced);
                if (Options.PersonaLive && stageLogs.TryGetValue(0, out var dnsLines) && dnsLines.Count > 0)
                    Ui.RenderPersonaLogPanel("DNS Activity", dnsLines);
                var allViews = hc.GetRecommendationViews();
                var dnsRecs = Ui.FilterRecommendationsForStage(allViews, 0).Take(5).ToArray();
                if (dnsRecs.Length > 0) Ui.RenderRecommendationsPanel("DNS Recommendations", dnsRecs);
                Ui.RenderMailTree(hc, advanced);
                if (Options.PersonaLive && stageLogs.TryGetValue(1, out var mailLines) && mailLines.Count > 0)
                    Ui.RenderPersonaLogPanel("Mail Activity", mailLines);
                var mailRecs = Ui.FilterRecommendationsForStage(allViews, 1).Take(5).ToArray();
                if (mailRecs.Length > 0) Ui.RenderRecommendationsPanel("Mail Recommendations", mailRecs);
                if (Options.Mode != ScanMode.Quick) Ui.RenderWebTree(hc, advanced);
                if (Options.PersonaLive && Options.Mode != ScanMode.Quick && stageLogs.TryGetValue(2, out var webLines) && webLines.Count > 0)
                    Ui.RenderPersonaLogPanel("Web Activity", webLines);
                if (Options.Mode != ScanMode.Quick)
                {
                    var webRecs = Ui.FilterRecommendationsForStage(allViews, 2).Take(5).ToArray();
                    if (webRecs.Length > 0) Ui.RenderRecommendationsPanel("Web Recommendations", webRecs);
                }
                if (Options.Mode == ScanMode.Full) Ui.RenderReputationTree(hc, advanced);
                if (Options.PersonaLive && Options.Mode == ScanMode.Full && stageLogs.TryGetValue(3, out var repLines) && repLines.Count > 0)
                    Ui.RenderPersonaLogPanel("Reputation Activity", repLines);
                if (Options.Mode == ScanMode.Full)
                {
                    var repRecs = Ui.FilterRecommendationsForStage(allViews, 3).Take(5).ToArray();
                    if (repRecs.Length > 0) Ui.RenderRecommendationsPanel("Reputation Recommendations", repRecs);
                }
            }

            // Persona-driven recommendations summary from assessments
            var assessments = hc.GetAllAssessments()?.ToArray() ?? Array.Empty<Assessment>();
            if (assessments.Length > 0)
            {
                var persona = Options.Persona?.ToLowerInvariant() switch {
                    "funny" => PersonaKind.Funny,
                    "geek"  => PersonaKind.Geek,
                    "noir"  => PersonaKind.Noir,
                    "pirate"=> PersonaKind.Pirate,
                    _ => PersonaKind.Business
                };
                var lines = PersonaFormatter.FormatSummary(assessments, persona, max: 12).ToArray();
                var panel = new Panel(new Markup(string.Join("\n", lines)))
                {
                    Header = new PanelHeader("[bold]🧭 Recommendations[/]"),
                    Border = BoxBorder.Rounded
                };
                AnsiConsole.Write(panel);
                AnsiConsole.WriteLine();
            }
        }

        return hc;
    }

    private static async Task RunDnsAsync(DomainHealthCheck hc, string domain, CancellationToken ct)
    {
        FxLog.Enqueue("[grey]> DNS: NS/SOA/DNSSEC/Wildcard/OpenResolver/AXFR/TTL…[/]");
        var checks = new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL };
        await hc.Verify(domain, checks, cancellationToken: ct);
        FxLog.Enqueue("[green]✓[/] DNS phase complete");
    }

    private static async Task RunMailAsync(DomainHealthCheck hc, string domain, bool activeProbes, CancellationToken ct)
    {
        FxLog.Enqueue("[grey]> Mail: MX/SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT…[/]");
        var checks = new List<HealthCheckType> { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT };
        if (activeProbes)
        {
            checks.AddRange(new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY });
        }
        await hc.Verify(domain, checks.ToArray(), cancellationToken: ct);
        FxLog.Enqueue("[green]✓[/] Mail phase complete");
    }

    private static async Task RunWebAsync(DomainHealthCheck hc, string domain, CancellationToken ct)
    {
        FxLog.Enqueue("[grey]> Web: HTTP/HSTS/SecHeaders + HTTPS/TLS + DANE…[/]");
        await hc.VerifyPlainHttp(domain, ct);
        await hc.VerifyWebsiteCertificate(domain, 443, ct);
        await hc.VerifyDANE(domain, new[] { ServiceType.HTTPS }, ct);
        FxLog.Enqueue("[green]✓[/] Web phase complete");
    }

    private static async Task RunReputationAsync(DomainHealthCheck hc, string domain, CancellationToken ct)
    {
        FxLog.Enqueue("[grey]> Reputation: WHOIS/RDAP/RPKI/DNSBL…[/]");
        await hc.Verify(domain, new[] { HealthCheckType.DNSBL }, cancellationToken: ct);
        await hc.CheckWHOIS(domain, ct);
        await hc.QueryRDAP(domain, ct);
        await hc.VerifyRPKI(domain, ct);
        FxLog.Enqueue("[green]✓[/] Reputation phase complete");
    }
}

file static class FxLog
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

file static class Fx
{
    internal sealed class MailPolicyScore { public int SpfCoverage { get; set; } public int DkimSelectors { get; set; } public int DmarcStrength { get; set; } public int TransportTlsPosture { get; set; } }
    private sealed class LiveModel { public ProgressTask? Dns; public ProgressTask? Mail; public ProgressTask? Web; public ProgressTask? Rep; }

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

file static class Ui
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
        if (advanced) spf.AddNode($"Lookups: {hc.SpfAnalysis?.DnsLookupsCount} / Exceeds10: {hc.SpfAnalysis?.ExceedsDnsLookups}");
        var dmarc = root.AddNode("[white]DMARC[/]");
        dmarc.AddNode((hc.DmarcAnalysis?.DmarcRecord ?? "—").EscapeMarkup());
        if (advanced)
        {
            dmarc.AddNode($"Policy: {hc.DmarcAnalysis?.Policy}");
            dmarc.AddNode($"Valid: {hc.DmarcAnalysis?.IsPolicyValid}");
        }
        var dkim = root.AddNode("[white]DKIM[/]");
        foreach (var kv in hc.DKIMAnalysis?.AnalysisResults ?? new Dictionary<string, DkimRecordAnalysis>())
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
