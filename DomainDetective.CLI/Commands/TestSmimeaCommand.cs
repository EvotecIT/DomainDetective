using Spectre.Console.Cli;
using System.Threading.Tasks;

namespace DomainDetective.CLI {
    internal sealed class TestSmimeaSettings : CommandSettings {
        [CommandArgument(0, "<email>")]
        public string Email { get; set; } = string.Empty;
    }

    internal sealed class TestSmimeaCommand : AsyncCommand<TestSmimeaSettings> {
        public override async Task<int> ExecuteAsync(CommandContext context, TestSmimeaSettings settings) {
            var hc = new DomainHealthCheck();
            await hc.VerifySMIMEA(settings.Email);
            CliHelpers.ShowPropertiesTable($"SMIMEA for {settings.Email}", hc.SmimeaAnalysis, false);
            return 0;
        }
    }
}
