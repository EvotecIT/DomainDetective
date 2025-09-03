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
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Launch the wizard.</summary>
    ///   <code>Invoke-DDDomainWizard</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Invoke, "DDDomainWizard")]
    [Alias("Invoke-DomainWizard")]
    [OutputType(typeof(DomainSummary), typeof(string))]
    public sealed class CmdletInvokeDomainWizard : AsyncPSCmdlet {
        /// <summary>
        /// Runs the interactive wizard that guides the user through domain
        /// verification.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            Host.UI.WriteLine("");
            Host.UI.WriteLine("╔══════════════════════════════════════════════════════════╗");
            Host.UI.WriteLine("║          DomainDetective Interactive Wizard             ║");
            Host.UI.WriteLine("║       Comprehensive Domain Security Analysis Tool       ║");
            Host.UI.WriteLine("╚══════════════════════════════════════════════════════════╝");
            Host.UI.WriteLine("");
            
            Host.UI.Write("Enter domain(s) [comma separated]: ");
            var domainInput = Host.UI.ReadLine();
            if (string.IsNullOrWhiteSpace(domainInput)) {
                WriteWarning("No domain provided.");
                return;
            }

            var domains = domainInput
                .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(d => d.Trim())
                .Where(d => d.Length > 0)
                .ToArray();

            // Enhanced check selection
            var checkSelection = Host.UI.PromptForChoice(
                "Check Selection",
                "What type of analysis would you like to perform?",
                new Collection<ChoiceDescription> {
                    new("&Quick", "Quick analysis - Essential checks only"),
                    new("&Full", "Full analysis - All available checks"),
                    new("&Email", "Email security focused (SPF, DKIM, DMARC)"),
                    new("&DNS", "DNS security focused (DNSSEC, CAA, DANE)"),
                    new("&Custom", "Custom - Select specific checks")
                },
                0);

            HealthCheckType[]? checks = null;
            switch (checkSelection) {
                case 0: // Quick
                    checks = new[] { 
                        HealthCheckType.SPF, HealthCheckType.DMARC, 
                        HealthCheckType.MX, HealthCheckType.NS 
                    };
                    break;
                case 1: // Full
                    checks = null; // null means all checks
                    break;
                case 2: // Email
                    checks = new[] { 
                        HealthCheckType.SPF, HealthCheckType.DMARC, 
                        HealthCheckType.DKIM, HealthCheckType.MX,
                        HealthCheckType.SMTPBANNER, HealthCheckType.ARC
                    };
                    break;
                case 3: // DNS
                    checks = new[] { 
                        HealthCheckType.DNSSEC, HealthCheckType.CAA, 
                        HealthCheckType.DANE, HealthCheckType.NS,
                        HealthCheckType.DELEGATION, HealthCheckType.ZONETRANSFER
                    };
                    break;
                case 4: // Custom
                    Host.UI.WriteLine("Available checks: " + string.Join(", ", Enum.GetNames(typeof(HealthCheckType))));
                    Host.UI.Write("Enter checks (comma separated): ");
                    var checksInput = Host.UI.ReadLine();
                    if (!string.IsNullOrWhiteSpace(checksInput)) {
                        var parts = checksInput
                            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                            .Select(p => p.Trim())
                            .Where(p => p.Length > 0);
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
                    break;
            }

            // Additional options
            var httpChoice = Host.UI.PromptForChoice(
                "HTTP Check",
                "Perform plain HTTP security check?",
                new Collection<ChoiceDescription> { new("&Yes"), new("&No") },
                1);
            var runHttp = httpChoice == 0;
            
            var takeoverChoice = Host.UI.PromptForChoice(
                "Subdomain Takeover",
                "Check for subdomain takeover vulnerabilities?",
                new Collection<ChoiceDescription> { new("&Yes"), new("&No") },
                1);
            var checkTakeover = takeoverChoice == 0;

            var outputChoice = Host.UI.PromptForChoice(
                "Output Format",
                "How would you like the results displayed?",
                new Collection<ChoiceDescription> { 
                    new("&Summary", "Condensed summary view"),
                    new("&Detailed", "Full detailed results"),
                    new("&JSON", "JSON format for automation")
                },
                1);
            var outputJson = outputChoice == 2;
            var summaryOnly = outputChoice == 0;

            Host.UI.WriteLine("");
            Host.UI.WriteLine("Starting analysis...");
            Host.UI.WriteLine("");

            foreach (var domain in domains) {
                Host.UI.WriteLine($"Analyzing domain: {domain}");
                Host.UI.WriteLine(new string('-', 50));
                
                var hc = new DomainHealthCheck { 
                    Verbose = false,
                    Progress = false // Disable progress for PowerShell
                };
                
                await hc.Verify(domain, checks);
                
                if (runHttp) {
                    await hc.VerifyPlainHttp(domain);
                }
                
                if (checkTakeover) {
                    await hc.VerifyTakeoverCname(domain);
                }
                
                if (outputJson) {
                    WriteObject(hc.ToJson());
                } else if (summaryOnly) {
                    var summary = hc.BuildSummary();
                    WriteObject(summary);
                    
                    // Display key summary info
                    Host.UI.WriteLine("");
                    Host.UI.WriteLine($"SPF: {(summary.HasSpfRecord ? (summary.SpfValid ? "✓ Valid" : "⚠ Invalid") : "✗ Missing")}");
                    Host.UI.WriteLine($"DMARC: {(summary.HasDmarcRecord ? (summary.DmarcValid ? $"✓ Valid ({summary.DmarcPolicy})" : "⚠ Invalid") : "✗ Missing")}");
                    Host.UI.WriteLine($"DKIM: {(summary.HasDkimRecord ? (summary.DkimValid ? "✓ Valid" : "⚠ Invalid") : "✗ Missing")}");
                    Host.UI.WriteLine($"MX: {(summary.HasMxRecord ? "✓ Present" : "✗ Missing")}");
                    Host.UI.WriteLine($"DNSSEC: {(summary.DnsSecValid ? "✓ Valid" : "✗ Not enabled")}");
                    
                    if (summary.ExpiresSoon) {
                        Host.UI.WriteLine($"⚠ Domain expires soon: {summary.ExpiryDate}");
                    }
                    if (summary.Hints?.Count > 0) {
                        Host.UI.WriteLine("");
                        Host.UI.WriteLine("Recommendations:");
                        foreach (var hint in summary.Hints.Take(5)) {
                            Host.UI.WriteLine($"  • {hint}");
                        }
                        if (summary.Hints.Count > 5) {
                            Host.UI.WriteLine($"  ... and {summary.Hints.Count - 5} more recommendations");
                        }
                    }
                } else {
                    // Detailed output
                    WriteObject(hc);
                    
                    // Also write key findings to host
                    var summary = hc.BuildSummary();
                    Host.UI.WriteLine("");
                    Host.UI.WriteLine("Quick Summary:");
                    Host.UI.WriteLine($"  SPF: {(summary.HasSpfRecord ? (summary.SpfValid ? "Valid" : "Invalid") : "Missing")}");
                    Host.UI.WriteLine($"  DMARC: {(summary.HasDmarcRecord ? (summary.DmarcValid ? $"Valid ({summary.DmarcPolicy})" : "Invalid") : "Missing")}");
                    Host.UI.WriteLine($"  DKIM: {(summary.HasDkimRecord ? (summary.DkimValid ? "Valid" : "Invalid") : "Missing")}");
                    Host.UI.WriteLine($"  DNSSEC: {(summary.DnsSecValid ? "Valid" : "Not enabled")}");
                    
                    if (summary.Hints?.Count > 0) {
                        Host.UI.WriteLine("");
                        Host.UI.WriteLine($"Found {summary.Hints.Count} recommendation(s). Use detailed output or generated report to see full details.");
                    }
                }
                
                Host.UI.WriteLine("");
            }
            
            Host.UI.WriteLine("Analysis complete!");
            Host.UI.WriteLine("");
        }
    }
}
