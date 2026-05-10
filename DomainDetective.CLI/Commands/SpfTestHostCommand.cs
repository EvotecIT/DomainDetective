using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace DomainDetective.CLI;

internal sealed class SpfTestHostSettings : CommandSettings
{
    [CommandArgument(0, "<domain>")]
    [Description("Domain to evaluate")] public string Domain { get; set; } = string.Empty;

    [CommandOption("--ip <IP>")]
    [Description("IPv4/IPv6 address to test")] public string Ip { get; set; } = string.Empty;

    [CommandOption("--sender <SENDER>")]
    [Description("Sender address for macro expansion")] public string? Sender { get; set; }

    [CommandOption("--helo <HELO>")]
    [Description("HELO/EHLO domain for macro expansion")] public string? Helo { get; set; }

    [CommandOption("--json")]
    [Description("Emit JSON output")] public bool Json { get; set; }
}

internal sealed class SpfTestHostCommand : AsyncCommand<SpfTestHostSettings>
{
    [RequiresDynamicCode("Calls DomainDetective.SpfAnalysis.EvaluateHostAsync")]
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize")] 
    protected override async Task<int> ExecuteAsync(CommandContext context, SpfTestHostSettings settings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.Domain))
        {
            AnsiConsole.MarkupLine("[red]Domain is required[/]");
            return 2;
        }
        if (!IPAddress.TryParse(settings.Ip, out var ip))
        {
            AnsiConsole.MarkupLine("[red]--ip must be a valid IPv4/IPv6 address[/]");
            return 2;
        }

        var logger = new InternalLogger(false);
        var hc = new DomainDetective.DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
        await hc.VerifySPF(settings.Domain);
        var sender = string.IsNullOrWhiteSpace(settings.Sender) ? $"postmaster@{settings.Domain}" : settings.Sender!;
        var helo = string.IsNullOrWhiteSpace(settings.Helo) ? $"mail.{settings.Domain}" : settings.Helo!;
        var eval = await hc.SpfAnalysis.EvaluateHostAsync(settings.Domain, ip, sender, helo, logger);

        if (settings.Json)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(eval, DomainDetective.Helpers.JsonOptions.Default);
            Console.WriteLine(json);
            return 0;
        }

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Field");
        table.AddColumn("Value");
        table.AddRow("Domain", settings.Domain);
        table.AddRow("IP", eval.IpAddress);
        table.AddRow("Sender", eval.Sender);
        table.AddRow("HELO", eval.Helo);
        table.AddRow("Verdict", eval.Verdict);
        table.AddRow("MatchedType", eval.MatchedType ?? string.Empty);
        table.AddRow("MatchedToken", eval.MatchedToken ?? string.Empty);
        table.AddRow("MatchedDomain", eval.MatchedDomain ?? string.Empty);
        table.AddRow("DNS Lookups", eval.DnsLookups.ToString());
        table.AddRow("LookupsExceeded", eval.LookupsExceeded.ToString());
        if (eval.Chain != null && eval.Chain.Count > 0)
        {
            table.AddRow("Chain", string.Join(" -> ", eval.Chain));
        }
        AnsiConsole.Write(table);
        return 0;
    }
}
