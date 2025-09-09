using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using DomainDetective.CLI.Wizard;
using DomainDetective.Scanning;

namespace DomainDetective.CLI;

/// <summary>Settings for the Hacker Wizard scan.</summary>
internal sealed class WizardScanSettings : CommandSettings
{
    [Description("Domain to scan (e.g. example.com)")]
    [CommandOption("--domain <DOMAIN>")]
    public string Domain { get; set; } = string.Empty;

    [Description("Run a quick scan (skip Web & Reputation)")]
    [CommandOption("--quick")]
    public bool Quick { get; set; }

    [Description("Run a full scan (includes Reputation)")]
    [CommandOption("--full")]
    public bool Full { get; set; }

    [Description("Output format: console|json|html")]
    [CommandOption("--output <FMT>")]
    [DefaultValue("console")]
    public string Output { get; set; } = "console";

    [Description("Path for JSON/HTML export")]
    [CommandOption("--out <PATH>")]
    public string? Out { get; set; }

    [Description("Disable ANSI coloring")]
    [CommandOption("--no-ansi")]
    public bool NoAnsi { get; set; }

    [Description("Matrix theme")]
    [CommandOption("--matrix")]
    public bool Matrix { get; set; }

    [Description("Enable active mail transport probes")]
    [CommandOption("--active-mail-probes")]
    public bool ActiveMailProbes { get; set; }

    [Description("Details level: summary|standard|advanced")]
    [CommandOption("--details <LEVEL>")]
    [DefaultValue("standard")]
    public string Details { get; set; } = "standard";

    [Description("Interactive selection of checks (checkboxes)")]
    [CommandOption("--interactive")]
    public bool Interactive { get; set; }

    [Description("Narration persona: business|funny|geek|noir|pirate")]
    [CommandOption("--persona <KIND>")]
    [DefaultValue("business")]
    public string Persona { get; set; } = "business";

    [Description("Show live persona narration during checks")]
    [CommandOption("--persona-live")]
    public bool PersonaLive { get; set; }

    [Description("Include verbose persona narration (info-level logs)")]
    [CommandOption("--persona-verbose")]
    public bool PersonaVerbose { get; set; }

    [Description("Keep console open after run and show next steps")]
    [CommandOption("--pause-exit")]
    public bool PauseExit { get; set; }

    [Description("Use simple streaming UI (no live layout)")]
    [CommandOption("--simple-ui")]
    public bool SimpleUi { get; set; }

    [Description("Use live UI layout (panels + progress)")]
    [CommandOption("--live-ui")]
    public bool LiveUi { get; set; }

    public override ValidationResult Validate()
    {
        // In interactive mode, domain is chosen via prompts; skip strict validation here
        if (!Interactive && string.IsNullOrWhiteSpace(Domain))
            return ValidationResult.Error("--domain is required");
        return ValidationResult.Success();
    }
}

/// <summary>Runs the Hacker Wizard scan with Spectre UI.</summary>
internal sealed class WizardScanCommand : AsyncCommand<WizardScanSettings>
{
    [RequiresDynamicCode("Calls JSON serialization")]
    public override async Task<int> ExecuteAsync(CommandContext context, WizardScanSettings s)
    {
        // Note: Spectre.Console global profile is read-only in this version.
        // We skip toggling ANSI here and rely on environment/terminal settings.
        if (s.Matrix)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.Clear();
        }

        bool runAgain;
        do
        {
            runAgain = false;

            var mode = s.Full ? DomainDetective.CLI.Wizard.ScanMode.Full : (s.Quick ? DomainDetective.CLI.Wizard.ScanMode.Quick : DomainDetective.CLI.Wizard.ScanMode.Default);

            HealthCheckType[]? selectedChecks = null;
            bool activeProbes = s.ActiveMailProbes;
            string details = s.Details.ToLowerInvariant();

            if (s.Interactive)
            {
                // Welcome
                AnsiConsole.Clear();
                var fig = new FigletText("DomainDetective").Color(Color.Green);
                AnsiConsole.Write(new Panel(fig) { Border = BoxBorder.Double, Header = new PanelHeader("[bold yellow]Welcome[/]") });

                // Main Settings (at start)
                var setup = AnsiConsole.Prompt(
                    new MultiSelectionPrompt<string>()
                        .Title("Scan setup — toggle options")
                        .InstructionsText("[grey](<space> to toggle, <enter> to continue)[/]")
                        .AddChoices(new[] {
                            "🎙 Live narration",
                            "🪵 Verbose details",
                            "🖨 Output: JSON",
                            "🖨 Output: HTML",
                            "🟩 Matrix theme",
                            "🧩 Animated panels UI"
                        })
                        .Select("🎙 Live narration")
                );
                s.PersonaLive = setup.Contains("🎙 Live narration");
                s.PersonaVerbose = setup.Contains("🪵 Verbose details");
                if (setup.Contains("🖨 Output: JSON") && setup.Contains("🖨 Output: HTML"))
                {
                    // Prefer JSON when both toggled; user can change later via flags
                    s.Output = "json";
                }
                else if (setup.Contains("🖨 Output: JSON")) s.Output = "json";
                else if (setup.Contains("🖨 Output: HTML")) s.Output = "html";
                s.Matrix = setup.Contains("🟩 Matrix theme");
                s.LiveUi = setup.Contains("🧩 Animated panels UI");
                s.SimpleUi = !s.LiveUi;

                // Recent domains or enter new
                var recent = RecentDomains.Load();
                var domainChoices = new List<string>();
                if (recent.Count > 0)
                {
                    domainChoices.AddRange(recent.Take(10).Select(d => $"📌 {d}"));
                }
                domainChoices.Add("➕ Enter new domain");
                var pickDomain = AnsiConsole.Prompt(new SelectionPrompt<string>()
                    .Title("Choose a domain")
                    .AddChoices(domainChoices));
                if (pickDomain.StartsWith("📌 "))
                {
                    s.Domain = pickDomain.Substring(2).Trim();
                }
                else
                {
                    s.Domain = AnsiConsole
                        .Prompt(new TextPrompt<string>("Enter domain:")
                            .PromptStyle("green")
                            .Validate(input =>
                            {
                                input = (input ?? string.Empty).Trim();
                                if (string.IsNullOrWhiteSpace(input))
                                    return ValidationResult.Error("Domain cannot be empty.");
                                if (input.Contains('/') || input.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                                    return ValidationResult.Error("Enter a bare domain (e.g., example.com), not a URL.");
                                if (!input.Contains('.'))
                                    return ValidationResult.Error("Domain should contain a dot (e.g., example.com).");
                                return ValidationResult.Success();
                            }))
                        .Trim();
                }

                // Scan mode menu (styled with icons)
                var modeChoice = AnsiConsole.Prompt(new SelectionPrompt<string>()
                    .Title($"Select scan mode for [bold]{s.Domain}[/]")
                    .AddChoices(new[] { "⚡ Quick", "🧪 Advanced", "🧩 Custom" })
                    .HighlightStyle(new Style(Color.Green))
                );

            var list = new List<HealthCheckType>();
            switch (modeChoice)
            {
                case var m when m.Contains("Quick", StringComparison.OrdinalIgnoreCase):
                    s.Quick = true; s.Full = false;
                        // DNS + Mail essential (balanced for speed)
                        list.AddRange(new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.MTASTS, HealthCheckType.TLSRPT });
                        break;
                    case var m when m.Contains("Advanced", StringComparison.OrdinalIgnoreCase):
                        s.Quick = false; s.Full = true;
                        // DNS + Mail + Web + Reputation
                        list.AddRange(new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL });
                        list.AddRange(new[] { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT });
                        list.AddRange(new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE });
                        list.AddRange(new[] { HealthCheckType.DNSBL, HealthCheckType.RPKI, HealthCheckType.RDAP });
                        // Mail probes option as part of Advanced
                        var wantProbes = AnsiConsole.Prompt(new SelectionPrompt<string>()
                            .Title("Active mail probes")
                            .AddChoices(new[] { "Skip", "Include" })
                            .HighlightStyle(new Style(Color.Green)));
                        activeProbes = wantProbes.Equals("Include", StringComparison.OrdinalIgnoreCase);
                        if (activeProbes)
                            list.AddRange(new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY });
                        break;
                    default: // Custom
                    {
                        var choices = new[]
                        {
                            "🧭 DNS",
                            "📧 Mail",
                            "🌐 Web",
                            "🛡 Reputation",
                            "⚙️ Active mail probes"
                        };
                        var picked = AnsiConsole.Prompt(
                            new MultiSelectionPrompt<string>()
                                .Title($"[green]Select what to scan for [bold]{s.Domain}[/]:[/]")
                                .InstructionsText("[grey](Press [yellow]<space>[/] to toggle, [yellow]<enter>[/] to accept)[/]")
                                .NotRequired()
                                .PageSize(10)
                                .HighlightStyle(new Style(Color.Green))
                                .AddChoices(choices)
                                .Select("🧭 DNS").Select("📧 Mail")
                        );
                        if (picked.Contains("🧭 DNS")) list.AddRange(new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL });
                        if (picked.Contains("📧 Mail"))
                        {
                            list.AddRange(new[] { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT });
                            if (picked.Contains("⚙️ Active mail probes"))
                            {
                                activeProbes = true;
                                list.AddRange(new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY });
                            }
                        }
                        if (picked.Contains("🌐 Web")) list.AddRange(new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE });
                        if (picked.Contains("🛡 Reputation")) list.AddRange(new[] { HealthCheckType.DNSBL, HealthCheckType.RPKI, HealthCheckType.RDAP });
                        // Infer Full if Reputation selected
                        s.Full = picked.Contains("🛡 Reputation"); s.Quick = !s.Full;
                        break;
                    }
                }
            selectedChecks = list.Distinct().ToArray();

            // Details level quick picker
            details = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("Details level")
                    .AddChoices(new[] { "standard", "summary", "advanced" })
                    .HighlightStyle(new Style(Color.Green))
            );

            
            }

            // Defaults: if user asked for verbose narration, ensure live is on; if neither specified, enable live by default
            if (s.PersonaVerbose) s.PersonaLive = true;
            if (!s.Interactive && !s.PersonaLive && !s.PersonaVerbose) s.PersonaLive = true;

        // Default UI: Simple/Testimo-style unless user opted in to live UI
        var wizard = new DomainWizard(new WizardOptions
        {
            Domain = s.Domain.Trim().ToLowerInvariant(),
            Mode = mode,
            Output = s.Output.ToLowerInvariant(),
            Out = s.Out,
            Matrix = s.Matrix,
            ActiveMailProbes = activeProbes,
            Details = details,
            Checks = selectedChecks,
            Persona = s.Persona,
            PersonaLive = s.PersonaLive,
            PersonaVerbose = s.PersonaVerbose,
            ShowTitle = !s.Interactive, // we already showed the Welcome header in interactive mode
            DisableLive = s.SimpleUi || !s.LiveUi
        });

            var hc = await wizard.RunAsync(Program.CancellationToken);
            // Save domain to recent list
            RecentDomains.Add(s.Domain);

            // Console summary: provider chain (primary, gateways, outbound)
            try
            {
                var pm = hc?.EmailProviderMatch;
                if (pm != null)
                {
                    var primary = pm.Primary?.DisplayName ?? "(unknown)";
                    var gateways = (pm.Gateways != null && pm.Gateways.Count > 0) ? string.Join(", ", pm.Gateways.Select(g => g.DisplayName).Distinct()) : "none";
                    var outbound = (pm.OutboundSenders != null && pm.OutboundSenders.Count > 0) ? string.Join(", ", pm.OutboundSenders.Select(o => o.DisplayName).Distinct()) : "none";
                    var panel = new Panel($"[bold]Primary:[/] {primary}\n[bold]Gateways:[/] {gateways}\n[bold]Outbound:[/] {outbound}")
                    {
                        Border = BoxBorder.Rounded,
                        Header = new PanelHeader("Mail Provider Chain", Justify.Center)
                    };
                    AnsiConsole.Write(panel);
                }
            } catch { }

            switch (wizard.Options.Output)
            {
                case "json":
                    {
                        var json = hc.ToJson();
                        if (!string.IsNullOrWhiteSpace(wizard.Options.Out))
                        {
                            File.WriteAllText(wizard.Options.Out!, json);
                            AnsiConsole.MarkupLine($"[grey]JSON written to[/] [underline]{wizard.Options.Out}[/]");
                        }
                        else
                        {
                            Console.WriteLine(json);
                        }
                        break;
                    }
                case "html":
                    {
                        AnsiConsole.MarkupLine("[yellow]HTML export is not enabled yet for the wizard.[/]");
                        break;
                    }
                default:
                    break;
            }

            // Post-run next-step menu to keep window open and allow re-runs
            if (s.Interactive || s.PauseExit)
            {
                AnsiConsole.WriteLine();
                var next = AnsiConsole.Prompt(new SelectionPrompt<string>()
                    .Title("What next?")
                    .AddChoices(new[] { "🔁 Run again", "🚪 Exit" })
                    .HighlightStyle(new Style(Color.Green))
                );
                if (next.StartsWith("🔁"))
                {
                    runAgain = true;
                    s.Interactive = true; // return to interactive prompts to choose other tests
                }
            }

        } while (runAgain && !Program.CancellationToken.IsCancellationRequested);

        return 0;
    }
}
