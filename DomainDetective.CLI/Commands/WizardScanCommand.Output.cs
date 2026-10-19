using DomainDetective.CLI.Wizard;
using Spectre.Console;

namespace DomainDetective.CLI;

internal sealed partial class WizardScanCommand {
    internal static int WriteScanOutputs(DomainHealthCheck health, WizardOptions options, string domain) {
        switch (options.Output) {
            case "json":
                if (!string.IsNullOrWhiteSpace(options.Out)) {
                    var path = WizardExportUtilities.WriteJson(health, options.Out!);
                    AnsiConsole.MarkupLine($"[grey]JSON written to[/] [underline]{path.EscapeMarkup()}[/]");
                } else {
                    System.Console.WriteLine(health.ToJson());
                }
                break;
            case "html":
                var htmlPath = WizardExportUtilities.WriteHtml(health, domain, options.Out);
                AnsiConsole.MarkupLine($"[grey]HTML written to[/] [underline]{htmlPath.EscapeMarkup()}[/]");
                break;
        }
        return health.VerificationCompleted == true ? 0 : 1;
    }
}
