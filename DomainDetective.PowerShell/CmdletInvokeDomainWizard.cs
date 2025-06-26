using DomainDetective;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Starts an interactive wizard to run domain checks.</summary>
    /// <example>
    ///   <summary>Launch the wizard.</summary>
    ///   <code>Invoke-DomainWizard</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Invoke, "DomainWizard")]
    [OutputType(typeof(DomainSummary), typeof(string))]
    public sealed class CmdletInvokeDomainWizard : AsyncPSCmdlet {
        protected override async Task ProcessRecordAsync() {
            Host.UI.WriteLine("DomainDetective wizard");
            Host.UI.Write("Enter domain(s) [comma separated]: ");
            var domainInput = Host.UI.ReadLine();
            if (string.IsNullOrWhiteSpace(domainInput)) {
                WriteWarning("No domain provided.");
                return;
            }

            var domains = domainInput.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            Host.UI.Write("Checks to run (comma separated, leave empty for all): ");
            var checksInput = Host.UI.ReadLine();
            HealthCheckType[]? checks = null;
            if (!string.IsNullOrWhiteSpace(checksInput)) {
                var parts = checksInput.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var list = new List<HealthCheckType>();
                foreach (var part in parts) {
                    if (Enum.TryParse(part, true, out HealthCheckType t)) {
                        list.Add(t);
                    } else {
                        WriteWarning($"Unknown check '{part}'");
                    }
                }
                if (list.Count > 0) {
                    checks = list.ToArray();
                }
            }

            var httpChoice = Host.UI.PromptForChoice(
                "HTTP",
                "Perform plain HTTP check?",
                new Collection<ChoiceDescription> { new("&Yes"), new("&No") },
                1);
            var runHttp = httpChoice == 0;
            var jsonChoice = Host.UI.PromptForChoice(
                "Output",
                "Output JSON?",
                new Collection<ChoiceDescription> { new("&Yes"), new("&No") },
                1);
            var outputJson = jsonChoice == 0;

            foreach (var domain in domains) {
                var hc = new DomainHealthCheck { Verbose = false };
                await hc.Verify(domain, checks);
                if (runHttp) {
                    await hc.VerifyPlainHttp(domain);
                }
                if (outputJson) {
                    WriteObject(hc.ToJson());
                    continue;
                }
                var summary = hc.BuildSummary();
                WriteObject(summary);
            }
        }
    }
}
