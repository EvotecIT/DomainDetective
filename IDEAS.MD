Absolutely—let’s give DomainDetective a **persona engine** so the scan can “talk” like a **funny**, **business**, or **geek** narrator (and you can add more later). Below is a **ready-to-commit** update that:

* Adds `--persona funny|business|geek|noir|pirate` to the CLI.
* Routes all conversational lines through a **ConvoLog** that styles phrasing, colors, icons, and emoji density per persona.
* Keeps parallel execution + Live progress from the last version.
* Exposes `-Persona` in the PowerShell wrappers.

---

## `DomainDetective.Cli/Program.cs` (with `--persona`)

```csharp
using System.CommandLine;
using DomainDetective.Cli.Wizard;
using Spectre.Console;

var domainOption = new Option<string>("--domain", "Domain to scan (e.g. example.com)") { IsRequired = true };
var quickOption  = new Option<bool>("--quick", "Run a quick scan (DNS + Mail summary)");
var fullOption   = new Option<bool>("--full", "Run a full audit (all modules)");
var outFmt       = new Option<string>("--output", () => "console", "Output format: console|json|html");
var outPath      = new Option<string>("--out", "Path for JSON/HTML export (file or folder).");
var noAnsi       = new Option<bool>("--no-ansi", "Disable ANSI (plain console).");
var darkTheme    = new Option<bool>("--matrix", "Force Matrix/green-on-black theme.");
var personaOpt   = new Option<string>("--persona", () => "business", "Narration persona: funny|business|geek|noir|pirate");

var root = new RootCommand("DomainDetective — Interactive Wizard");
root.AddOption(domainOption);
root.AddOption(quickOption);
root.AddOption(fullOption);
root.AddOption(outFmt);
root.AddOption(outPath);
root.AddOption(noAnsi);
root.AddOption(darkTheme);
root.AddOption(personaOpt);

root.SetHandler(async (string domain, bool quick, bool full, string output, string? outFile, bool noColors, bool matrix, string persona) =>
{
    AnsiConsole.Profile = new Profile(capabilities: new Capabilities(emojis: true, links: true, ansi: !noColors));
    if (matrix)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.BackgroundColor = ConsoleColor.Black;
        Console.Clear();
    }

    var wizard = new DomainWizard(new WizardOptions
    {
        Domain  = domain.Trim().ToLowerInvariant(),
        Mode    = full ? ScanMode.Full : (quick ? ScanMode.Quick : ScanMode.Default),
        Output  = output.ToLowerInvariant(),     // console|json|html
        Out     = outFile,
        Matrix  = matrix,
        Persona = PersonaProfiles.ParseOrDefault(persona)
    });

    var result = await wizard.RunAsync();

    switch (wizard.Options.Output)
    {
        case "json":
            {
                var json = Exporters.JsonExporter.Serialize(result);
                if (!string.IsNullOrWhiteSpace(wizard.Options.Out))
                {
                    System.IO.File.WriteAllText(wizard.Options.Out!, json);
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
                var html = Exporters.HtmlExporter.Render(result, wizard.Options);
                if (!string.IsNullOrWhiteSpace(wizard.Options.Out))
                {
                    System.IO.File.WriteAllText(wizard.Options.Out!, html);
                    AnsiConsole.MarkupLine($"[grey]HTML written to[/] [underline]{wizard.Options.Out}[/]");
                }
                else
                {
                    Console.WriteLine(html);
                }
                break;
            }
        default:
            break;
    }

}, domainOption, quickOption, fullOption, outFmt, outPath, noAnsi, darkTheme, personaOpt);

return await root.InvokeAsync(args);
```

---

## `DomainDetective.Cli/Wizard/Wizard.cs` (persona engine + conversational log)

```csharp
using Spectre.Console;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;

namespace DomainDetective.Cli.Wizard;

// ---------- Options, Modes, Persona ----------
public enum ScanMode { Default, Quick, Full }

public sealed class WizardOptions
{
    public required string Domain { get; init; }
    public ScanMode Mode { get; init; } = ScanMode.Default;
    public string Output { get; init; } = "console"; // console|json|html
    public string? Out { get; init; }
    public bool Matrix { get; init; } = false;
    public PersonaProfile Persona { get; init; } = PersonaProfiles.Business;
}

// Persona profile (colors, icons, phrasing)
public sealed class PersonaProfile
{
    public required string Name { get; init; }
    public required string StageTagColor { get; init; }     // e.g. "bold cyan"
    public required string StepColor { get; init; }          // e.g. "cyan"
    public required string OkColor { get; init; }            // "green"
    public required string WarnColor { get; init; }          // "yellow"
    public required string ErrColor { get; init; }           // "red"
    public required string PromptIcon { get; init; }         // "»", "→", etc.
    public required string OkIcon { get; init; }             // "✓"
    public required string WarnIcon { get; init; }           // "⚠"
    public required string ErrIcon { get; init; }            // "✖"
    public required string[] StepVerbs { get; init; }        // "Checking", "Analyzing"
    public required string[] OkPhrases { get; init; }        // "Looks good", "All set"
    public required string[] WarnPhrases { get; init; }      // "Suspicious", "Needs attention"
    public required string[] ErrPhrases { get; init; }       // "Broken", "Failing"
    public double EmojiDensity { get; init; }                // 0..1 likelihood to append emoji
    public string[] Emojis { get; init; } = Array.Empty<string>();
    public int StepTypeSpeedMs { get; init; } = 16;          // typewriter speed
    public int ResultTypeSpeedMs { get; init; } = 12;
}

public static class PersonaProfiles
{
    public static readonly PersonaProfile Business = new()
    {
        Name="business",
        StageTagColor="bold steelblue1",
        StepColor="deepskyblue1",
        OkColor="green3",
        WarnColor="khaki1",
        ErrColor="red3",
        PromptIcon="»",
        OkIcon="✓",
        WarnIcon="⚠",
        ErrIcon="✖",
        StepVerbs=new[]{"Checking","Verifying","Evaluating","Assessing","Analyzing"},
        OkPhrases=new[]{"Confirmed","All good","Compliant","Healthy","Meets policy"},
        WarnPhrases=new[]{"Needs attention","Advisory","Degraded","Weak posture","Consider changes"},
        ErrPhrases=new[]{"Non-compliant","Failed","Broken","Critical","Blocking"},
        EmojiDensity=0.05,
        Emojis=new[]{"📈","🧭","🧩"},
        StepTypeSpeedMs=12,
        ResultTypeSpeedMs=8
    };

    public static readonly PersonaProfile Funny = new()
    {
        Name="funny",
        StageTagColor="bold green3",
        StepColor="springgreen1",
        OkColor="green3",
        WarnColor="yellow1",
        ErrColor="red1",
        PromptIcon="→",
        OkIcon="✅",
        WarnIcon="🤨",
        ErrIcon="💥",
        StepVerbs=new[]{"Peeking at","Poking","Sniffing","Tickling","Investigating"},
        OkPhrases=new[]{"Niiiice","Chef’s kiss","Rock solid","Green as grass","Ship it"},
        WarnPhrases=new[]{"Little sus","Hmmmm","I’ve seen better","Keep an eye","Could be spicier"},
        ErrPhrases=new[]{"Oof","Yikes","Nope nope nope","On fire","Hard fail"},
        EmojiDensity=0.35,
        Emojis=new[]{"😎","🧪","🦾","✨","🛟"},
        StepTypeSpeedMs=10,
        ResultTypeSpeedMs=8
    };

    public static readonly PersonaProfile Geek = new()
    {
        Name="geek",
        StageTagColor="bold magenta",
        StepColor="orchid1",
        OkColor="chartreuse1",
        WarnColor="gold1",
        ErrColor="deeppink1",
        PromptIcon="➜",
        OkIcon="✔",
        WarnIcon="⚠",
        ErrIcon="✘",
        StepVerbs=new[]{"Resolving","Parsing","Diffing","Enumerating","Fingerprinting"},
        OkPhrases=new[]{"LGTM","Spec-compliant","Deterministic","Idempotent","Consistent"},
        WarnPhrases=new[]{"Non-ideal","Edge-case","Heuristic match","Low entropy","Suboptimal"},
        ErrPhrases=new[]{"Invariant violated","Assertion failed","Null ref IRL","Out-of-spec","Catastrophic"},
        EmojiDensity=0.15,
        Emojis=new[]{"🧬","📚","🧠","🔬"},
        StepTypeSpeedMs=8,
        ResultTypeSpeedMs=6
    };

    public static readonly PersonaProfile Noir = new()
    {
        Name="noir",
        StageTagColor="bold grey66",
        StepColor="grey78",
        OkColor="aquamarine1",
        WarnColor="lightgoldenrod1",
        ErrColor="indianred1",
        PromptIcon="›",
        OkIcon="●",
        WarnIcon="◐",
        ErrIcon="○",
        StepVerbs=new[]{"Shadowing","Trailing","Interrogating","Dusting for prints on","Tailoring the lead on"},
        OkPhrases=new[]{"Clean as a whistle","Checks out","Nothing suspicious","Buttoned up","Solid alibi"},
        WarnPhrases=new[]{"Smells funny","Watch this angle","Loose thread","Shaky alibi","Keep digging"},
        ErrPhrases=new[]{"Caught red-handed","Dead end","Leaking bad","Open secret","Crime scene"},
        EmojiDensity=0.08,
        Emojis=new[]{"🕵️","🖤","🚬"},
        StepTypeSpeedMs=12,
        ResultTypeSpeedMs=10
    };

    public static readonly PersonaProfile Pirate = new()
    {
        Name="pirate",
        StageTagColor="bold yellow1",
        StepColor="gold1",
        OkColor="green1",
        WarnColor="yellow1",
        ErrColor="red1",
        PromptIcon="⚓",
        OkIcon="☠",
        WarnIcon="🏴‍☠️",
        ErrIcon="🗡",
        StepVerbs=new[]{"Chartin’","Spyglassin’","Soundin’","Boardin’","Pillagin’"},
        OkPhrases=new[]{"Fair winds","Aye, solid","Shipshape","Treasure found","Ports secured"},
        WarnPhrases=new[]{"Reef ahead","Storm brewin’","Trim the sails","Keep a weather eye","Careful, ye lubber"},
        ErrPhrases=new[]{"Scuttled","Keelhauled","Breach below","Mutiny!","Dead in the water"},
        EmojiDensity=0.3,
        Emojis=new[]{"🏴‍☠️","🦜","🗺️","⚓"},
        StepTypeSpeedMs=10,
        ResultTypeSpeedMs=8
    };

    public static PersonaProfile ParseOrDefault(string v)
    {
        return (v ?? "").Trim().ToLowerInvariant() switch
        {
            "funny" => Funny,
            "geek" => Geek,
            "noir" => Noir,
            "pirate" => Pirate,
            _ => Business
        };
    }
}

// ---------- Result Models ----------
public sealed class ScanResult
{
    public string Domain { get; init; } = "";
    public DateTime StartedUtc { get; init; } = DateTime.UtcNow;
    public DateTime FinishedUtc { get; set; }

    public DnsResult Dns { get; init; } = new();
    public MailResult Mail { get; init; } = new();
    public WebResult Web { get; init; } = new();
    public ReputationResult Reputation { get; init; } = new();

    public List<string> Notes { get; } = new();
}

public sealed class DnsResult
{
    public SoaInfo? Soa { get; set; }
    public List<string> Ns { get; set; } = new();
    public List<MxInfo> Mx { get; set; } = new();
    public bool? DnssecEnabled { get; set; }
    public bool? ZoneTransferOpen { get; set; }
    public bool? WildcardDetected { get; set; }
    public bool? OpenResolver { get; set; }
    public TimeSpan? MinTtl { get; set; }
    public TimeSpan? MaxTtl { get; set; }
    public List<PTRInfo> Reverse { get; set; } = new();
    public bool? FCrDnsAligned { get; set; }
}

public sealed class MailResult
{
    public string? SpfRecord { get; set; }
    public string? DmarcRecord { get; set; }
    public string? DkimSelectorHint { get; set; }
    public Dictionary<string, bool?> DkimSelectorsOk { get; set; } = new();
    public string? BimiRecord { get; set; }
    public string? MtaStsPolicy { get; set; }
    public string? TlsRpt { get; set; }

    public bool? SmtpStartTlsOk { get; set; }
    public bool? ImapTlsOk { get; set; }
    public bool? Pop3TlsOk { get; set; }
    public bool? OpenRelaySuspected { get; set; }

    public MailPolicyScore PolicyScore { get; set; } = new();
}

public sealed class WebResult
{
    public bool? HttpOk { get; set; }
    public bool? HttpsOk { get; set; }
    public bool? Http2 { get; set; }
    public bool? Http3 { get; set; }
    public bool? Hsts { get; set; }
    public List<string> SecurityHeadersMissing { get; set; } = new();
    public TlsChainInfo? Tls { get; set; }
    public bool? DaneTlsa { get; set; }
    public bool? SMIMEA { get; set; }
}

public sealed class ReputationResult
{
    public string? WhoisRegistrar { get; set; }
    public string? RdapHandle { get; set; }
    public bool? RpkiValid { get; set; }
    public List<string> Blacklists { get; set; } = new();
}

// ---------- Submodels ----------
public sealed class SoaInfo { public string? PrimaryNs { get; set; } public string? RName { get; set; } public long? Serial { get; set; } }
public sealed class MxInfo { public string Host { get; set; } = ""; public int Preference { get; set; } public bool? Resolvable { get; set; } }
public sealed class PTRInfo { public string Ip { get; set; } = ""; public string? Ptr { get; set; } }
public sealed class TlsChainInfo { public string? Subject { get; set; } public string? Issuer { get; set; } public DateTimeOffset? NotAfter { get; set; } }
public sealed class MailPolicyScore { public int SpfCoverage { get; set; } public int DkimSelectors { get; set; } public int DmarcStrength { get; set; } public int TransportTlsPosture { get; set; } }

// ---------- Log bus (producer: analyzers, consumer: UI) ----------
file static class FxLog
{
    private static readonly Channel<string> _bus = Channel.CreateUnbounded<string>();
    public static void Enqueue(string markup) => _bus.Writer.TryWrite(markup);
    public static async Task ConsumeAsync(CancellationToken ct)
    {
        await foreach (var line in _bus.Reader.ReadAllAsync(ct))
            await Fx.TypeLineAsync(line);
    }
    public static void Complete() => _bus.Writer.TryComplete();
}

// ---------- Conversational logger with persona ----------
public sealed class Convo
{
    private readonly string _stageTag; // e.g. "[DNS]"
    private readonly PersonaProfile _p;

    public Convo(string stage, PersonaProfile p)
    {
        _p = p;
        _stageTag = $"[{_p.StageTagColor}]{stage}[/]";
    }

    private static readonly Random _rng = new();

    private string MaybeEmoji()
        => _rng.NextDouble() <= _p.EmojiDensity && _p.Emojis.Length > 0 ? " " + _p.Emojis[_rng.Next(_p.Emojis.Length)] : "";

    private string Pick(string[] arr) => arr.Length == 0 ? "" : arr[_rng.Next(arr.Length)];

    public async Task Step(string thing) =>
        await Fx.TypeLineAsync($"{_stageTag} [ {_p.StepColor}]{Pick(_p.StepVerbs)} {thing}…[/]", _p.StepTypeSpeedMs);

    public async Task Ok(string detail) =>
        await Fx.TypeLineAsync($"{_p.PromptIcon} [ {_p.OkColor}]{_p.OkIcon} {Pick(_p.OkPhrases)}[/]: {detail}{MaybeEmoji()}", _p.ResultTypeSpeedMs);

    public async Task Warn(string detail) =>
        await Fx.TypeLineAsync($"{_p.PromptIcon} [ {_p.WarnColor}]{_p.WarnIcon} {Pick(_p.WarnPhrases)}[/]: {detail}{MaybeEmoji()}", _p.ResultTypeSpeedMs);

    public async Task Err(string detail) =>
        await Fx.TypeLineAsync($"{_p.PromptIcon} [ {_p.ErrColor}]{_p.ErrIcon} {Pick(_p.ErrPhrases)}[/]: {detail}{MaybeEmoji()}", _p.ResultTypeSpeedMs);

    // Non-typewriter (for background threads via bus)
    public void StepQueued(string thing) =>
        FxLog.Enqueue($"{_stageTag} [ {_p.StepColor}]{Pick(_p.StepVerbs)} {thing}…[/]");
    public void OkQueued(string detail) =>
        FxLog.Enqueue($"{_p.PromptIcon} [ {_p.OkColor}]{_p.OkIcon} {Pick(_p.OkPhrases)}[/]: {detail}{MaybeEmoji()}");
    public void WarnQueued(string detail) =>
        FxLog.Enqueue($"{_p.PromptIcon} [ {_p.WarnColor}]{_p.WarnIcon} {Pick(_p.WarnPhrases)}[/]: {detail}{MaybeEmoji()}");
    public void ErrQueued(string detail) =>
        FxLog.Enqueue($"{_p.PromptIcon} [ {_p.ErrColor}]{_p.ErrIcon} {Pick(_p.ErrPhrases)}[/]: {detail}{MaybeEmoji()}");
}

// ---------- Wizard ----------
public sealed class DomainWizard
{
    public WizardOptions Options { get; }
    public DomainWizard(WizardOptions options) => Options = options;

    public async Task<ScanResult> RunAsync()
    {
        var res = new ScanResult { Domain = Options.Domain };

        if (Options.Output == "console")
            Fx.TitleScreen(Options.Domain, Options.Matrix, Options.Persona);

        using var cts = new CancellationTokenSource();
        var logConsumer = FxLog.ConsumeAsync(cts.Token);

        // Parallel analyzers; each uses Convo(...).XxxQueued for narration
        var tasks = new List<Func<Task>>
        {
            () => AnalyzeDnsAsync(res),
            () => AnalyzeMailAsync(res),
            () => AnalyzeWebMaybeAsync(res),
            () => AnalyzeReputationMaybeAsync(res)
        };

        await Fx.RunParallelWithLiveAsync(tasks);

        FxLog.Complete();
        cts.Cancel();
        try { await logConsumer; } catch { }

        res.FinishedUtc = DateTime.UtcNow;

        if (Options.Output == "console")
        {
            Fx.FinalSummary(res);
            Ui.RenderDnsTree(res.Dns, res.Domain);
            Ui.RenderMailSummary(res.Mail);
            Ui.RenderWebSummary(res.Web);
            Ui.RenderReputationSummary(res.Reputation);
        }

        return res;
    }

    // ---------- Analyzer placeholders (now with persona narration) ----------
    private async Task AnalyzeDnsAsync(ScanResult result)
    {
        var talk = new Convo("DNS", Options.Persona);
        talk.StepQueued($"NS for [white]{result.Domain}[/]");
        await Task.Delay(200);
        result.Dns.Ns = new() { $"ns1.{result.Domain}", $"ns2.{result.Domain}" };
        talk.OkQueued($"NS: [green]{string.Join(", ", result.Dns.Ns)}[/]");

        talk.StepQueued("SOA serial");
        await Task.Delay(120);
        result.Dns.Soa = new SoaInfo { PrimaryNs = $"ns1.{result.Domain}", RName = "hostmaster." + result.Domain, Serial = 2025082501 };
        talk.OkQueued($"SOA: [yellow]{result.Dns.Soa.Serial}[/]");

        talk.StepQueued("MX discovery");
        await Task.Delay(140);
        result.Dns.Mx = new()
        {
            new MxInfo { Host = $"mx1.{result.Domain}", Preference = 10, Resolvable = true },
            new MxInfo { Host = $"mx2.{result.Domain}", Preference = 20, Resolvable = true },
        };
        talk.OkQueued($"MX: [green]{string.Join(", ", result.Dns.Mx.OrderBy(x=>x.Preference).Select(x=>$"{x.Preference} {x.Host}"))}[/]");

        talk.StepQueued("DNSSEC / wildcard / AXFR / TTL");
        await Task.Delay(160);
        result.Dns.DnssecEnabled = true;
        result.Dns.WildcardDetected = false;
        result.Dns.OpenResolver = false;
        result.Dns.ZoneTransferOpen = false;
        result.Dns.MinTtl = TimeSpan.FromMinutes(5);
        result.Dns.MaxTtl = TimeSpan.FromHours(24);
        talk.OkQueued($"DNSSEC [green]enabled[/], AXFR [green]closed[/], TTL [white]{result.Dns.MinTtl}[/]–[white]{result.Dns.MaxTtl}[/]");
    }

    private async Task AnalyzeMailAsync(ScanResult result)
    {
        var talk = new Convo("MAIL", Options.Persona);
        talk.StepQueued("SPF / DMARC / BIMI TXT");
        await Task.Delay(160);
        result.Mail.SpfRecord   = $"v=spf1 include:_spf.{result.Domain} -all";
        result.Mail.DmarcRecord = "v=DMARC1; p=reject; rua=mailto:dmarc@" + result.Domain;
        result.Mail.BimiRecord  = "v=BIMI1; l=https://example.com/logo.svg; a=self";
        talk.OkQueued($"SPF: [white]{result.Mail.SpfRecord}[/], DMARC: [white]{result.Mail.DmarcRecord}[/]");

        talk.StepQueued("DKIM selectors");
        await Task.Delay(120);
        result.Mail.DkimSelectorHint = "Try: default, selector1, google";
        result.Mail.DkimSelectorsOk["default"]  = true;
        result.Mail.DkimSelectorsOk["selector1"] = true;
        result.Mail.DkimSelectorsOk["google"]   = null;
        talk.WarnQueued("DKIM [white]google[/] unresolved; others OK");

        talk.StepQueued("MTA-STS / TLS-RPT");
        await Task.Delay(120);
        result.Mail.MtaStsPolicy = "mode=enforce; mx: mx1." + result.Domain;
        result.Mail.TlsRpt      = "v=TLSRPTv1; rua=mailto:tlsrpt@" + result.Domain;
        talk.OkQueued("MTA-STS enforce; TLS-RPT configured");

        result.Mail.PolicyScore = new MailPolicyScore { SpfCoverage = 90, DkimSelectors = 75, DmarcStrength = 100, TransportTlsPosture = 80 };
    }

    private async Task AnalyzeWebMaybeAsync(ScanResult result)
    {
        var talk = new Convo("WEB", Options.Persona);
        if (Options.Mode == ScanMode.Quick)
        {
            talk.WarnQueued("Skipped in Quick mode");
            return;
        }

        talk.StepQueued("HTTP/HTTPS/H2/H3/HSTS");
        await Task.Delay(200);
        result.Web.HttpOk  = true;
        result.Web.HttpsOk = true;
        result.Web.Http2   = true;
        result.Web.Http3   = false;
        result.Web.Hsts    = true;
        result.Web.SecurityHeadersMissing = new();

        result.Web.Tls = new TlsChainInfo
        {
            Subject = $"CN={result.Domain}",
            Issuer = "R3 (Let’s Encrypt)",
            NotAfter = DateTimeOffset.UtcNow.AddDays(60)
        };
        result.Web.DaneTlsa = false;
        result.Web.SMIMEA   = false;

        talk.OkQueued("HTTPS + H2 OK; H3 unavailable; TLS chain valid");
    }

    private async Task AnalyzeReputationMaybeAsync(ScanResult result)
    {
        var talk = new Convo("REP", Options.Persona);
        if (Options.Mode != ScanMode.Full)
        {
            talk.WarnQueued("Skipped (use --full)");
            return;
        }

        talk.StepQueued("WHOIS/RDAP/RPKI");
        await Task.Delay(200);
        result.Reputation.WhoisRegistrar = "Example Registrar LLC";
        result.Reputation.RdapHandle     = "RDAP-XYZ-123";
        result.Reputation.RpkiValid      = true;
        result.Reputation.Blacklists     = new();

        talk.OkQueued("Registrar resolved; RPKI valid; no blacklists");
    }
}

// ---------- UI Runtime (Live + Progress + Typewriter + Final) ----------
file static class Fx
{
    private sealed class LiveModel
    {
        public ProgressTask? Dns;
        public ProgressTask? Mail;
        public ProgressTask? Web;
        public ProgressTask? Rep;
    }

    public static void TitleScreen(string domain, bool matrix, PersonaProfile p)
    {
        var rule = new Rule($"[bold green]DOMAINDETECTIVE[/] [grey]// Wizard[/]") { Alignment = Justify.Center };
        AnsiConsole.Write(rule);
        AnsiConsole.MarkupLine($"[{p.StageTagColor}]Persona[/]: [bold]{p.Name}[/]");
        AnsiConsole.MarkupLine($"[green]Target:[/] [bold]{domain}[/]");
        if (matrix) AnsiConsole.MarkupLine("[grey]Theme:[/] [green]Matrix[/]");
        AnsiConsole.WriteLine();
    }

    public static async Task TypeLineAsync(string markup, int delayMs = 8)
    {
        foreach (var ch in markup)
        {
            AnsiConsole.Markup(ch.ToString());
            await Task.Delay(delayMs);
        }
        AnsiConsole.WriteLine();
    }

    public static async Task RunParallelWithLiveAsync(IReadOnlyList<Func<Task>> analyzers)
    {
        var liveModel = new LiveModel();

        await AnsiConsole.Live(new Rows()).StartAsync(async ctx =>
        {
            var progress = new Progress()
                .AutoClear(false)
                .HideCompleted(false)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn()
                });

            ctx.UpdateTarget(progress);

            await AnsiConsole.Progress()
                .AutoClear(false)
                .StartAsync(async prog =>
                {
                    liveModel.Dns  = prog.AddTask("DNS", autoStart: false, maxValue: 100);
                    liveModel.Mail = prog.AddTask("Mail", autoStart: false, maxValue: 100);
                    liveModel.Web  = prog.AddTask("Web", autoStart: false, maxValue: 100);
                    liveModel.Rep  = prog.AddTask("Reputation", autoStart: false, maxValue: 100);

                    var runners = new List<Task>
                    {
                        Task.Run(async () => { liveModel.Dns!.StartTask();  await analyzers[0](); liveModel.Dns.Value  = 100; }),
                        Task.Run(async () => { liveModel.Mail!.StartTask(); await analyzers[1](); liveModel.Mail.Value = 100; }),
                        Task.Run(async () => { liveModel.Web!.StartTask();  await analyzers[2](); liveModel.Web.Value  = 100; }),
                        Task.Run(async () => { liveModel.Rep!.StartTask();  await analyzers[3](); liveModel.Rep.Value  = 100; }),
                    };

                    await Task.WhenAll(runners);
                });

            ctx.UpdateTarget(new Panel(new Markup("[green]All stages completed[/]")) { Border = BoxBorder.Rounded, Header = new PanelHeader("[bold]Scan[/]") });
        });
    }

    public static void FinalSummary(ScanResult res)
    {
        var grid = new Grid().AddColumn().AddColumn();
        grid.AddRow(new Markup("[bold]Domain[/]"), new Markup(res.Domain));
        grid.AddRow(new Markup("[bold]Started[/]"), new Markup(res.StartedUtc.ToString("u")));
        grid.AddRow(new Markup("[bold]Finished[/]"), new Markup(res.FinishedUtc.ToString("u")));

        var p = new Panel(grid) { Header = new PanelHeader("[bold]Scan Complete[/]"), Border = BoxBorder.Heavy };
        AnsiConsole.Write(p);
        AnsiConsole.WriteLine();
    }

    public static string Bool(bool? v) => v == true ? "[green]OK[/]" : v == false ? "[red]NO[/]" : "[yellow]?[/]";

    public static Panel PostureBars(MailPolicyScore s)
    {
        var bars = new BarChart().Width(36);
        bars.AddItem("SPF",  s.SpfCoverage,         s.SpfCoverage         >= 85 ? Color.Green : s.SpfCoverage         >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("DKIM", s.DkimSelectors,       s.DkimSelectors       >= 85 ? Color.Green : s.DkimSelectors       >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("DMARC",s.DmarcStrength,       s.DmarcStrength       >= 85 ? Color.Green : s.DmarcStrength       >= 60 ? Color.Yellow : Color.Red);
        bars.AddItem("TLS",  s.TransportTlsPosture, s.TransportTlsPosture >= 85 ? Color.Green : s.TransportTlsPosture >= 60 ? Color.Yellow : Color.Red);
        return new Panel(bars) { Header = new PanelHeader("[bold]Email Posture[/]"), Border = BoxBorder.Rounded };
    }
}

// ---------- Final Renderers ----------
file static class Ui
{
    public static void RenderDnsTree(DnsResult dns, string domain)
    {
        var root = new Tree($"[bold]DNS for {domain}[/]");

        var ns = root.AddNode("[white]NS[/]");
        foreach (var n in dns.Ns) ns.AddNode($"[green]{n.EscapeMarkup()}[/]");

        var soa = root.AddNode("[white]SOA[/]");
        if (dns.Soa is not null)
        {
            soa.AddNode($"MNAME: [yellow]{dns.Soa.PrimaryNs?.EscapeMarkup()}[/]");
            soa.AddNode($"RNAME: [yellow]{dns.Soa.RName?.EscapeMarkup()}[/]");
            soa.AddNode($"Serial: [yellow]{dns.Soa.Serial}[/]");
        }

        var mx = root.AddNode("[white]MX[/]");
        foreach (var m in dns.Mx.OrderBy(x => x.Preference))
            mx.AddNode($"{m.Preference} [green]{m.Host.EscapeMarkup()}[/] {(m.Resolvable==true?"[green]OK[/]":"[red]NX[/]")}");

        var posture = new Panel(new Rows(
            new Markup($"DNSSEC: {Fx.Bool(dns.DnssecEnabled)}"),
            new Markup($"Wildcard: {Fx.Bool(!(dns.WildcardDetected==true))}"),
            new Markup($"Open Resolver: {Fx.Bool(!(dns.OpenResolver==true))}"),
            new Markup($"AXFR: {Fx.Bool(!(dns.ZoneTransferOpen==true))}"),
            new Markup($"TTL(min): {dns.MinTtl?.ToString()??"—"}"),
            new Markup($"TTL(max): {dns.MaxTtl?.ToString()??"—"}")
        ))
        { Header = new PanelHeader("[bold]DNS Posture[/]"), Border = BoxBorder.Rounded };

        var layout = new Grid().AddColumn().AddColumn();
        layout.AddRow(root, posture);

        AnsiConsole.Write(layout);
        AnsiConsole.WriteLine();
    }

    public static void RenderMailSummary(MailResult m)
    {
        var tree = new Tree("[bold]Email[/]");
        tree.AddNode("[white]SPF[/]").AddNode((m.SpfRecord ?? "—").EscapeMarkup());
        tree.AddNode("[white]DMARC[/]").AddNode((m.DmarcRecord ?? "—").EscapeMarkup());

        var dkim = tree.AddNode("[white]DKIM[/]");
        foreach (var kv in m.DkimSelectorsOk)
            dkim.AddNode($"{kv.Key}: {(kv.Value==true?"[green]OK[/]": kv.Value==false?"[red]FAIL[/]":"[yellow]?[/]")}");

        var details = new Panel(new Rows(
            new Markup($"BIMI: {(m.BimiRecord ?? "—").EscapeMarkup()}"),
            new Markup($"MTA-STS: {(m.MtaStsPolicy ?? "—").EscapeMarkup()}"),
            new Markup($"TLS-RPT: {(m.TlsRpt ?? "—").EscapeMarkup()}"),
            new Markup($"Hint: {(m.DkimSelectorHint ?? "—").EscapeMarkup()}")
        )) { Header = new PanelHeader("[bold]Email Details[/]"), Border = BoxBorder.Rounded };

        var grid = new Grid().AddColumn().AddColumn();
        grid.AddRow(tree, Fx.PostureBars(m.PolicyScore));

        AnsiConsole.Write(grid);
        AnsiConsole.Write(details);
        AnsiConsole.WriteLine();
    }

    public static void RenderWebSummary(WebResult web)
    {
        var kv = new Dictionary<string, string?>
        {
            ["HTTP"]     = Fx.Bool(web.HttpOk),
            ["HTTPS"]    = Fx.Bool(web.HttpsOk),
            ["HTTP/2"]   = Fx.Bool(web.Http2),
            ["HTTP/3"]   = Fx.Bool(web.Http3),
            ["HSTS"]     = Fx.Bool(web.Hsts),
            ["Missing"]  = web.SecurityHeadersMissing.Count == 0 ? "none" : string.Join(", ", web.SecurityHeadersMissing),
            ["TLS.Subject"] = web.Tls?.Subject,
            ["TLS.Issuer"]  = web.Tls?.Issuer,
            ["TLS.NotAfter"]= web.Tls?.NotAfter?.ToString("u"),
            ["DANE/TLSA"]   = Fx.Bool(web.DaneTlsa),
            ["S/MIMEA"]     = Fx.Bool(web.SMIMEA),
        };

        var rows = new List<IRenderable>();
        foreach (var p in kv)
            rows.Add(new Markup($"[grey]{p.Key}:[/] {p.Value?.EscapeMarkup() ?? "—"}"));

        var panel = new Panel(new Rows(rows)) { Header = new PanelHeader("[bold]Web[/]"), Border = BoxBorder.Rounded };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static void RenderReputationSummary(ReputationResult rep)
    {
        var rows = new Rows(
            new Markup($"Registrar: {(rep.WhoisRegistrar ?? "—").EscapeMarkup()}"),
            new Markup($"RDAP: {(rep.RdapHandle ?? "—").EscapeMarkup()}"),
            new Markup($"RPKI: {Fx.Bool(rep.RpkiValid)}"),
            new Markup($"Blacklists: {(rep.Blacklists.Count==0 ? "none" : string.Join(\", \", rep.Blacklists).EscapeMarkup())}")
        );
        var panel = new Panel(rows) { Header = new PanelHeader("[bold]Reputation & Registry[/]"), Border = BoxBorder.Rounded };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
}

// ---------- Exporters ----------
namespace Exporters
{
    public static class JsonExporter
    {
        private static readonly JsonSerializerOptions _opts = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public static string Serialize(ScanResult res) => JsonSerializer.Serialize(res, _opts);
    }

    public static class HtmlExporter
    {
        public static string Render(ScanResult res, WizardOptions options)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>DomainDetective Report</title>");
            sb.AppendLine("<style>body{font-family:ui-sans-serif,system-ui;background:#0b0f10;color:#e5f2e5} .ok{color:#6ee7a8}.bad{color:#f87171}.warn{color:#fbbf24} .card{border:1px solid #1f2937;padding:12px;border-radius:8px;margin:10px;background:#111827}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h1>DomainDetective — {res.Domain}</h1>");
            sb.AppendLine("<div class='card'><h2>DNS</h2>");
            sb.Append("<ul>");
            foreach (var ns in res.Dns.Ns) sb.Append($"<li>NS: {ns}</li>");
            foreach (var mx in res.Dns.Mx.OrderBy(m => m.Preference)) sb.Append($"<li>MX: {mx.Preference} {mx.Host} {(mx.Resolvable==true?"✅":"❌")}</li>");
            sb.Append($"<li>DNSSEC: {(res.Dns.DnssecEnabled==true?"✅":"❌")}</li>");
            sb.Append($"<li>AXFR: {(res.Dns.ZoneTransferOpen==true?"❌ open":"✅ closed")}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Email</h2><ul>");
            sb.Append($"<li>SPF: {res.Mail.SpfRecord}</li>");
            sb.Append($"<li>DMARC: {res.Mail.DmarcRecord}</li>");
            sb.Append($"<li>BIMI: {res.Mail.BimiRecord}</li>");
            sb.Append($"<li>MTA-STS: {res.Mail.MtaStsPolicy}</li>");
            sb.Append($"<li>TLS-RPT: {res.Mail.TlsRpt}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Web</h2><ul>");
            sb.Append($"<li>HTTP: {(res.Web.HttpOk==true?"✅":"❌")} / HTTPS: {(res.Web.HttpsOk==true?"✅":"❌")}</li>");
            sb.Append($"<li>H2: {(res.Web.Http2==true?"✅":"❌")} / H3: {(res.Web.Http3==true?"✅":"❌")}</li>");
            sb.Append($"<li>HSTS: {(res.Web.Hsts==true?"✅":"❌")}</li>");
            if (res.Web.Tls is not null)
                sb.Append($"<li>TLS: {res.Web.Tls.Subject} / {res.Web.Tls.Issuer} / NotAfter {res.Web.Tls.NotAfter:u}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("<div class='card'><h2>Reputation</h2><ul>");
            sb.Append($"<li>Registrar: {res.Reputation.WhoisRegistrar}</li>");
            sb.Append($"<li>RDAP: {res.Reputation.RdapHandle}</li>");
            sb.Append($"<li>RPKI: {(res.Reputation.RpkiValid==true?"✅":"❌")}</li>");
            if (res.Reputation.Blacklists.Count>0)
                sb.Append($"<li>Blacklists: {string.Join(", ", res.Reputation.Blacklists)}</li>");
            sb.Append("</ul></div>");

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
```

---

## `PowerShell/DomainDetective.psm1` (with `-Persona`)

```powershell
function Get-DomainDetectiveCliPath {
    param([string] $Path)
    if ($Path) { return $Path }
    $moduleRoot = Split-Path -Parent $PSCommandPath
    $candidate  = Join-Path $moduleRoot "DomainDetective.Cli.exe"
    if (Test-Path $candidate) { return $candidate }
    throw "DomainDetective.Cli.exe not found. Provide -Path."
}

function Start-DomainDetectiveWizard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Domain,
        [ValidateSet("funny","business","geek","noir","pirate")] [string] $Persona = "business",
        [switch] $Quick,
        [switch] $Full,
        [switch] $Matrix,
        [string] $Path
    )
    $exe = Get-DomainDetectiveCliPath -Path $Path
    $args = @("--domain", $Domain, "--output", "console", "--persona", $Persona)
    if ($Quick)  { $args += "--quick" }
    if ($Full)   { $args += "--full" }
    if ($Matrix) { $args += "--matrix" }
    & $exe @args
}

function Invoke-DomainDetectiveScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Domain,
        [ValidateSet("console","json","html")] [string] $Output = "json",
        [ValidateSet("funny","business","geek","noir","pirate")] [string] $Persona = "business",
        [string] $Out,
        [switch] $Quick,
        [switch] $Full,
        [string] $Path
    )
    $exe = Get-DomainDetectiveCliPath -Path $Path
    $args = @("--domain", $Domain, "--output", $Output, "--persona", $Persona)
    if ($Out)  { $args += @("--out", $Out) }
    if ($Quick) { $args += "--quick" }
    if ($Full)  { $args += "--full" }

    if ($Output -eq "json" -and -not $Out) {
        $json = & $exe @args | Out-String
        if (-not $json) { return }
        $obj = $json | ConvertFrom-Json -Depth 8
        return $obj
    } else {
        & $exe @args
    }
}
Export-ModuleMember -Function Start-DomainDetectiveWizard, Invoke-DomainDetectiveScan
```

---

## How it feels (examples)

**Funny**

```
[MAIL] Investigating SPF / DMARC / BIMI TXT…
→ ✅ Niiiice: SPF v=spf1 include:_spf.example.com -all 😎
→ 🤨 Little sus: DKIM google unresolved
```

**Business**

```
[DNS] Checking NS for example.com…
» ✓ Confirmed: NS ns1.example.com, ns2.example.com
» ✓ Compliant: DNSSEC enabled; AXFR closed
```

**Geek**

```
[WEB] Parsing HTTP/HTTPS/H2/H3/HSTS…
➜ ✔ Spec-compliant: H2 negotiated; H3 absent; TLS chain valid 🧬
```

---

## Extend personas

Add another `PersonaProfile` in `PersonaProfiles` and whitelist it in Program.cs & PowerShell `ValidateSet`. Tune:

* `StepVerbs`, `Ok/Warn/ErrPhrases`
* Colors, icons, `EmojiDensity`
* Typing speeds (`StepTypeSpeedMs`, `ResultTypeSpeedMs`)

---

Use it like:

```
./DomainDetective.Cli.exe --domain example.com --full --persona funny --matrix
Start-DomainDetectiveWizard -Domain example.com -Full -Persona geek -Matrix
```

This gives you a lively, colored, persona-driven “conversation” during the scan while preserving the robust parallel execution and clean final summaries.
