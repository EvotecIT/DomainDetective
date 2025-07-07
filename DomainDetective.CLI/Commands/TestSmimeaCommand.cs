using Spectre.Console.Cli;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.CLI {
    /// <summary>
    /// Settings for <see cref="TestSmimeaCommand"/>.
    /// </summary>
    internal sealed class TestSmimeaSettings : CommandSettings {
        /// <summary>Email address to test.</summary>
        [CommandArgument(0, "<email>")]
        public string Email { get; set; } = string.Empty;
    }

    /// <summary>
    /// Validates S/MIMEA records for a mailbox.
    /// </summary>
    internal sealed class TestSmimeaCommand : AsyncCommand<TestSmimeaSettings> {
        /// <inheritdoc/>
        public override async Task<int> ExecuteAsync(CommandContext context, TestSmimeaSettings settings) {
            var hc = new DomainHealthCheck();
            var email = settings.Email;
            var at = email.IndexOf('@');
            if (at > 0) {
                var local = email[..at];
                var domain = email[(at + 1)..];
                email = $"{local}@{CliHelpers.ToAscii(domain)}";
            }
            await hc.VerifySMIMEA(email, Program.CancellationToken);
            CliHelpers.ShowPropertiesTable($"SMIMEA for {settings.Email}", hc.SmimeaAnalysis, false);
            return 0;
        }
    }
}
