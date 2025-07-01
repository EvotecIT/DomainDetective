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
            var email = settings.Email;
            var at = email.IndexOf('@');
            if (at > 0) {
                var local = email[..at];
                var domain = email[(at + 1)..];
                email = $"{local}@{CliHelpers.ToAscii(domain)}";
            }
            await hc.VerifySMIMEA(email);
            CliHelpers.ShowPropertiesTable($"SMIMEA for {settings.Email}", hc.SmimeaAnalysis, false);
            return 0;
        }
    }
}
