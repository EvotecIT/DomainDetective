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
                var verb = PersonaLexicon.StepVerb(personaKind, ht.ToString());
                var friendly = Ui.FriendlyOpName(ht);
                var stepColor = PersonaFormatter.StepColor(personaKind);
                var desc = $"{stages[idx].Title} [{stepColor}]{verb} {friendly}[/]";
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
                var verb = PersonaLexicon.StepVerb(personaKind, ht.ToString());
                var stepColor = PersonaFormatter.StepColor(personaKind);
                stageOp[idx] = $"[{stepColor}]{verb} {Ui.FriendlyOpName(ht)}[/]";
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
                    var verb = PersonaLexicon.StepVerb(personaKind, ht.ToString());
                    sOp[idx] = $"{verb} {Ui.FriendlyOpName(ht)}";
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

                        // Persona stage start
                        var stageName = Ui.FriendlyStageName(i);
                        var verbStart = PersonaLexicon.StepVerb(personaKind, $"Stage:{stageName}");
                        AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Start", $"{verbStart} {stageName}");
                        if (stageLastLine.TryGetValue(i, out var startLine)) AppendGlobal(startLine);

                        try
                        {
                            await hc.Verify(Options.Domain, types, cancellationToken: ct);
                            if (i == 3 /* Reputation */)
                            {
                                await hc.CheckWHOIS(Options.Domain, ct);
                            }

                            // Persona stage finish
                            AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Done", $"Completed {stageName}");
                            if (stageLastLine.TryGetValue(i, out var doneLine)) AppendGlobal(doneLine);
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

                        // Persona stage start
                        var stageName = Ui.FriendlyStageName(i);
                        var verbStart = PersonaLexicon.StepVerb(personaKind, $"Stage:{stageName}");
                        AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Start", $"{verbStart} {stageName}");
                        var startLine = PersonaFormatter.Format(new Assessment { Severity = AssessmentSeverity.Info, Code = $"{stageName}.Start", Message = $"{verbStart} {stageName}" }, personaKind);
                        AppendGlobal(startLine);

                        try
                        {
                            await hc.Verify(Options.Domain, types, cancellationToken: ct);
                            if (i == 3 /* Reputation */)
                            {
                                await hc.CheckWHOIS(Options.Domain, ct);
                            }

                            // Persona stage finish
                            AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Done", $"Completed {stageName}");
                            var doneLine = PersonaFormatter.Format(new Assessment { Severity = AssessmentSeverity.Info, Code = $"{stageName}.Done", Message = $"Completed {stageName}" }, personaKind);
                            AppendGlobal(doneLine);
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

                // Area/Check Status Summaries (compact, scannable)
                Ui.RenderCheckSummariesPanel(hc, Options.ActiveMailProbes, Options.Mode);
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

