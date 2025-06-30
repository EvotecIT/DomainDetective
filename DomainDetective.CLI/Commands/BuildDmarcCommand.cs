using Spectre.Console;
using Spectre.Console.Cli;

namespace DomainDetective.CLI;

internal sealed class BuildDmarcCommand : Command<CommandSettings> {
    public override int Execute(CommandContext context, CommandSettings settings) {
        var policy = AnsiConsole.Prompt(new SelectionPrompt<string>()
            .Title("Select policy (p)")
            .AddChoices("none", "quarantine", "reject"));

        var subPolicy = AnsiConsole.Prompt(new SelectionPrompt<string>()
            .Title("Subdomain policy (sp) [inherit if blank]")
            .AddChoices("inherit", "none", "quarantine", "reject"));

        var rua = AnsiConsole.Ask<string>("Aggregate report URI (rua) [optional]", string.Empty);
        var ruf = AnsiConsole.Ask<string>("Forensic report URI (ruf) [optional]", string.Empty);
        var pct = AnsiConsole.Ask<int?>("Percentage (pct) [0-100, optional]", null);
        var adkim = AnsiConsole.Prompt(new SelectionPrompt<string>()
            .Title("DKIM alignment (adkim) [optional]")
            .AddChoices("default", "r", "s"));
        var aspf = AnsiConsole.Prompt(new SelectionPrompt<string>()
            .Title("SPF alignment (aspf) [optional]")
            .AddChoices("default", "r", "s"));
        var fo = AnsiConsole.Ask<string>("Failure options (fo) [optional]", string.Empty);
        var ri = AnsiConsole.Ask<int?>("Reporting interval (ri) [optional]", null);

        var parts = new List<string> { "v=DMARC1", $"p={policy}" };
        if (!string.IsNullOrWhiteSpace(rua)) parts.Add($"rua={rua}");
        if (!string.IsNullOrWhiteSpace(ruf)) parts.Add($"ruf={ruf}");
        if (pct.HasValue) parts.Add($"pct={pct.Value}");
        if (!string.IsNullOrWhiteSpace(subPolicy) && subPolicy != "inherit") parts.Add($"sp={subPolicy}");
        if (adkim != "default") parts.Add($"adkim={adkim}");
        if (aspf != "default") parts.Add($"aspf={aspf}");
        if (!string.IsNullOrWhiteSpace(fo)) parts.Add($"fo={fo}");
        if (ri.HasValue) parts.Add($"ri={ri.Value}");

        var record = string.Join("; ", parts) + ";";
        AnsiConsole.MarkupLine($"[green]{record}[/]");
        return 0;
    }
}
