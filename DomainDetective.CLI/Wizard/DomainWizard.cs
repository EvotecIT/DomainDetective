using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
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

public sealed partial class DomainWizard
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
        try { return await RunCoreAsync(hc, ilog, ct).ConfigureAwait(false); }
        catch { hc.Dispose(); throw; }
    }

    private async Task<DomainHealthCheck> RunCoreAsync(DomainHealthCheck hc, InternalLogger ilog, CancellationToken ct) {
        var (stages, plan) = BuildPlan(Options);

        var typeToStage = new Dictionary<HealthCheckType, int>();
        for (int i = 0; i < stages.Count; i++)
            if (stages[i].Enabled)
                foreach (var t in stages[i].Types) typeToStage[t] = i;

        // Persona live narration buffer per stage
        async Task RunPlanAsync() => await hc.Verify(Options.Domain, plan, cancellationToken: ct,
            useDefaultChecksWhenEmpty: false).ConfigureAwait(false);

        var completedChecks = new ConcurrentDictionary<HealthCheckType, byte>();
        int StagePercent(HealthCheckType type, int stage, int? completedSteps) {
            // The sequential core sends a start event with the previous step
            // count. Parallel events are completions and can arrive out of order.
            if ((hc.ExecutionOptions.EnableParallelism && plan.Length > 1) || completedSteps > completedChecks.Count) {
                completedChecks.TryAdd(type, 0);
            }
            var types = stages[stage].Types;
            return types.Length == 0 ? 100 : types.Count(completedChecks.ContainsKey) * 100 / types.Length;
        }
        var stageLogs = new ConcurrentDictionary<int, List<string>>();
        var stageLastLine = new ConcurrentDictionary<int, string>();
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
            var category = code?.Split('.')[0] ?? string.Empty;
            int stage = Enum.TryParse<HealthCheckType>(category, true, out var type) && typeToStage.TryGetValue(type, out var mapped)
                ? mapped : currentStageIdx;
            lock (stageLogs) {
                if (!stageLogs.TryGetValue(stage, out var list)) { list = new List<string>(); stageLogs[stage] = list; }
                list.Add(line);
                if (list.Count > 50) list.RemoveAt(0);
                stageLastLine[stage] = line;
            }
        }

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
            var liveLines = new ConcurrentQueue<string>();
            var progressLineNeedsRedraw = false;
            var termLock = new object();
            string ComposeProgressLine(ConcurrentDictionary<int,int> progress, ConcurrentDictionary<int,string> ops)
            {
                var parts = new List<string>();
                string[] names = new[] { "DNS", "Mail", "Web", "Rep", "Other" };
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
                liveLines.Enqueue(compact);
                while (liveLines.Count > 400) { liveLines.TryDequeue(out _); }
                if (!canLive)
                {
                    // In simple UI, print log on a fresh line and re-draw status pinned line
                    lock (termLock)
                    {
                        if (AnsiConsole.Profile.Capabilities.Ansi) { Console.Write("\r\x1b[2K"); }
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

            var stageProgress = new ConcurrentDictionary<int, int>();
            var stageOp = new ConcurrentDictionary<int, string>();
            for (int i = 0; i < stages.Count; i++) if (stages[i].Enabled) stageProgress[i] = 0;

            ilog.OnProgressMessage += (_, e) =>
            {
                if (!Enum.TryParse<HealthCheckType>(e.ProgressCurrentOperation ?? string.Empty, ignoreCase: true, out var ht)) return;
                if (!typeToStage.TryGetValue(ht, out var fullIdx)) return;
                var idx = fullIdx;
                stageProgress[idx] = StagePercent(ht, fullIdx, e.ProgressCurrentSteps);
                var verb = PersonaLexicon.StepVerb(personaKind, ht.ToString());
                var stepColor = PersonaFormatter.StepColor(personaKind);
                stageOp[idx] = $"[{stepColor}]{verb} {Ui.FriendlyOpName(ht)}[/]";
            };

            var layout = new Layout("root")
                .SplitRows(
                    new Layout("log").Ratio(3),
                    new Layout("prog").Ratio(1)
                );

            static Table BuildProgressTable(List<(string Title, HealthCheckType[] Types, bool Enabled)> stages, ConcurrentDictionary<int,int> progress, ConcurrentDictionary<int,string> ops)
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
                var sProgress = new ConcurrentDictionary<int, int>();
                var sOp = new ConcurrentDictionary<int, string>();
                for (int i = 0; i < stages.Count; i++) if (stages[i].Enabled) sProgress[i] = 0;
                ilog.OnProgressMessage += (_, e) =>
                {
                    if (!Enum.TryParse<HealthCheckType>(e.ProgressCurrentOperation ?? string.Empty, ignoreCase: true, out var ht)) return;
                    if (!typeToStage.TryGetValue(ht, out var fullIdx)) return;
                    var idx = fullIdx;
                    sProgress[idx] = StagePercent(ht, fullIdx, e.ProgressCurrentSteps);
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
                                if (AnsiConsole.Profile.Capabilities.Ansi) { Console.Write("\r\x1b[2K"); }
                                if (!string.IsNullOrEmpty(line)) {
                                    if (AnsiConsole.Profile.Capabilities.Ansi) { Console.Write(line); }
                                    else { Console.WriteLine(line); }
                                }
                                progressLineNeedsRedraw = false;
                            }
                        }
                        await Task.Delay(120, ctsProg.Token).ConfigureAwait(false);
                    }
                }, ctsProg.Token);

                try
                {
                    await RunPlanAsync();
                    for (int i = 0; i < stages.Count; i++) {
                        if (!stages[i].Enabled) continue;
                        currentStageIdx = i;
                        var stageName = Ui.FriendlyStageName(i);
                        AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Done", $"Completed {stageName}");
                        if (stageLastLine.TryGetValue(i, out var line)) AppendGlobal(line);
                        sProgress[i] = 100;
                    }
                    progressLineNeedsRedraw = true;
                }
                finally
                {
                    // finalize progress line
                    ctsProg.Cancel();
                    try { await progTask; } catch { /* ignore */ }
                    lock (termLock)
                    {
                        if (AnsiConsole.Profile.Capabilities.Ansi) { Console.Write("\r\x1b[2K\n"); }
                        else { Console.WriteLine(); }
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
                    try {
                        await RunPlanAsync();
                        for (int i = 0; i < stages.Count; i++) {
                            if (!stages[i].Enabled) continue;
                            currentStageIdx = i;
                            var stageName = Ui.FriendlyStageName(i);
                            AppendPersonaLine(AssessmentSeverity.Info, $"{stageName}.Done", $"Completed {stageName}");
                            stageProgress[i] = 100;
                        }
                    } finally { done = true; }
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
            await RunPlanAsync();
        }

        if (Options.Output == "console")
        {
            bool customSelection = Options.Checks != null && Options.Checks.Length > 0;
            var advanced = Options.Details.Equals("advanced", StringComparison.OrdinalIgnoreCase);
            var summaryOnly = Options.Details.Equals("summary", StringComparison.OrdinalIgnoreCase);

            if (customSelection) {
                AnsiConsole.MarkupLine($"[green]Selected checks completed for {Options.Domain.EscapeMarkup()}[/]");
                if (!summaryOnly) {
                    var analyses = hc.GetAnalysisMap();
                    foreach (var check in plan) {
                        if (analyses.TryGetValue(check, out var analysis) && analysis != null) {
                            CliHelpers.ShowPropertiesTable($"{check} for {Options.Domain}", analysis, false);
                        }
                    }
                }
            } else {
                Fx.FinalSummary(hc, Options.Domain);
                Ui.RenderPosturePanels(hc);
                if (!summaryOnly)
                {
                    if (stages[0].Enabled) { Ui.RenderDnsTree(hc, advanced); }
                    if (Options.PersonaLive && stageLogs.TryGetValue(0, out var dnsLines) && dnsLines.Count > 0)
                        Ui.RenderPersonaLogPanel("DNS Activity", dnsLines);
                    var allViews = hc.GetRecommendationViews();
                    var dnsRecs = Ui.FilterRecommendationsForStage(allViews, 0).Take(5).ToArray();
                    if (dnsRecs.Length > 0) Ui.RenderRecommendationsPanel("DNS Recommendations", dnsRecs);
                    if (stages[1].Enabled) { Ui.RenderMailTree(hc, advanced); }
                    if (Options.PersonaLive && stageLogs.TryGetValue(1, out var mailLines) && mailLines.Count > 0)
                        Ui.RenderPersonaLogPanel("Mail Activity", mailLines);
                    var mailRecs = Ui.FilterRecommendationsForStage(allViews, 1).Take(5).ToArray();
                    if (mailRecs.Length > 0) Ui.RenderRecommendationsPanel("Mail Recommendations", mailRecs);
                    if (stages[2].Enabled) Ui.RenderWebTree(hc, advanced);
                    if (Options.PersonaLive && stages[2].Enabled && stageLogs.TryGetValue(2, out var webLines) && webLines.Count > 0)
                        Ui.RenderPersonaLogPanel("Web Activity", webLines);
                    if (stages[2].Enabled)
                    {
                        var webRecs = Ui.FilterRecommendationsForStage(allViews, 2).Take(5).ToArray();
                        if (webRecs.Length > 0) Ui.RenderRecommendationsPanel("Web Recommendations", webRecs);
                    }
                    if (stages[3].Enabled) Ui.RenderReputationTree(hc, advanced);
                    if (Options.PersonaLive && stages[3].Enabled && stageLogs.TryGetValue(3, out var repLines) && repLines.Count > 0)
                        Ui.RenderPersonaLogPanel("Reputation Activity", repLines);
                    if (stages[3].Enabled)
                    {
                        var repRecs = Ui.FilterRecommendationsForStage(allViews, 3).Take(5).ToArray();
                        if (repRecs.Length > 0) Ui.RenderRecommendationsPanel("Reputation Recommendations", repRecs);
                    }

                    var displayedMode = stages[3].Enabled ? ScanMode.Full : stages[2].Enabled ? ScanMode.Default : ScanMode.Quick;
                    Ui.RenderCheckSummariesPanel(hc, Options.ActiveMailProbes, displayedMode);
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

}
