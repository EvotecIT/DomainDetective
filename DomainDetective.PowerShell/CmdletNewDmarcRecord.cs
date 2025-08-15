using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Net.Http;
using System.Threading.Tasks;
using DomainDetective;
using Spectre.Console;

namespace DomainDetective.PowerShell {
    /// <summary>Builds a DMARC record string.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Create a DMARC record.</summary>
    ///   <code>New-DDDmarcRecord -Policy reject -AggregateUri mailto:reports@example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.New, "DDDmarcRecord")]
    [Alias("New-DmarcRecord")]
    [OutputType(typeof(string))]
    public sealed class CmdletNewDmarcRecord : AsyncPSCmdlet {
        /// <summary>Main DMARC policy.</summary>
        [Parameter(Position = 0)]
        [ValidateSet("none", "quarantine", "reject")]
        public string Policy { get; set; }

        /// <summary>Policy applied to subdomains.</summary>
        [Parameter]
        [ValidateSet("none", "quarantine", "reject")]
        public string SubPolicy { get; set; }

        /// <summary>Aggregate report URI(s).</summary>
        [Parameter]
        public string AggregateUri { get; set; }

        /// <summary>Forensic report URI(s).</summary>
        [Parameter]
        public string ForensicUri { get; set; }

        /// <summary>Percentage of mail subjected to the policy.</summary>
        [Parameter]
        [ValidateRange(0, 100)]
        public int? Percent { get; set; }

        /// <summary>DKIM alignment mode.</summary>
        [Parameter]
        [ValidateSet("r", "s")]
        public string DkimAlignment { get; set; }

        /// <summary>SPF alignment mode.</summary>
        [Parameter]
        [ValidateSet("r", "s")]
        public string SpfAlignment { get; set; }

        /// <summary>Failure reporting options.</summary>
        [Parameter]
        public string FailureOptions { get; set; }

        /// <summary>Reporting interval in seconds.</summary>
        [Parameter]
        public int? ReportingInterval { get; set; }

        /// <summary>Domain name for publishing.</summary>
        [Parameter]
        public string DomainName { get; set; }

        /// <summary>DNS provider API endpoint.</summary>
        [Parameter]
        public Uri DnsApiUrl { get; set; }

        /// <summary>Publish the record via DNS provider.</summary>
        [Parameter]
        public SwitchParameter Publish { get; set; }

        /// <summary>Prompt step by step for all options.</summary>
        [Parameter]
        public SwitchParameter StepByStep { get; set; }

        /// <summary>
        /// Prompts for parameters when <see cref="StepByStep"/> is specified.
        /// </summary>
        protected override Task BeginProcessingAsync() {
            if (StepByStep) {
                PromptForParameters();
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Builds and outputs the final DMARC record string.
        /// </summary>
        protected override async Task EndProcessingAsync() {
            var parts = new List<string> { "v=DMARC1", $"p={Policy}" };
            if (!string.IsNullOrWhiteSpace(SubPolicy)) {
                parts.Add($"sp={SubPolicy}");
            }
            if (!string.IsNullOrWhiteSpace(AggregateUri)) {
                parts.Add($"rua={AggregateUri}");
            }
            if (!string.IsNullOrWhiteSpace(ForensicUri)) {
                parts.Add($"ruf={ForensicUri}");
            }
            if (Percent.HasValue) {
                parts.Add($"pct={Percent.Value}");
            }
            if (!string.IsNullOrWhiteSpace(DkimAlignment)) {
                parts.Add($"adkim={DkimAlignment}");
            }
            if (!string.IsNullOrWhiteSpace(SpfAlignment)) {
                parts.Add($"aspf={SpfAlignment}");
            }
            if (!string.IsNullOrWhiteSpace(FailureOptions)) {
                parts.Add($"fo={FailureOptions}");
            }
            if (ReportingInterval.HasValue) {
                parts.Add($"ri={ReportingInterval.Value}");
            }
            var record = string.Join("; ", parts) + ";";
            WriteObject(record);
            AnsiConsole.MarkupLine($"[green]{Markup.Escape(record)}[/]");
            if (Publish) {
                await PublishRecordAsync(record).ConfigureAwait(false);
            }
        }

        private async Task PublishRecordAsync(string record) {
            if (DnsApiUrl == null || string.IsNullOrWhiteSpace(DomainName)) {
                WriteWarning("DnsApiUrl and DomainName are required for publishing.");
                return;
            }
            try {
                var client = SharedHttpClient.Instance;
                var data = new Dictionary<string, string> {
                    ["domain"] = DomainName,
                    ["record"] = record
                };
                using var response = await client.PostAsync(DnsApiUrl, new FormUrlEncodedContent(data)).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) {
                    WriteWarning($"Publish failed: {response.StatusCode}");
                }
            } catch (Exception ex) {
                WriteWarning($"Publish failed: {ex.Message}");
            }
        }

        private void PromptForParameters() {
            Policy ??= AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title(":shield: [green]Select policy (p)[/]")
                .AddChoices("none", "quarantine", "reject"));

            var sub = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title(":house: Subdomain policy (sp) [inherit if blank]")
                .AddChoices("inherit", "none", "quarantine", "reject"));
            SubPolicy = sub == "inherit" ? null : sub;

            AggregateUri = AnsiConsole.Ask("📬 Aggregate report URI (rua) [optional]", AggregateUri ?? string.Empty);
            ForensicUri = AnsiConsole.Ask("📝 Forensic report URI (ruf) [optional]", ForensicUri ?? string.Empty);
            Percent = AnsiConsole.Ask<int?>("Percent (pct) [0-100, optional]", Percent);

            var adkim = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("DKIM alignment (adkim) [optional]")
                .AddChoices("default", "r", "s"));
            DkimAlignment = adkim == "default" ? null : adkim;

            var aspf = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("SPF alignment (aspf) [optional]")
                .AddChoices("default", "r", "s"));
            SpfAlignment = aspf == "default" ? null : aspf;

            FailureOptions = AnsiConsole.Ask("Failure options (fo) [optional]", FailureOptions ?? string.Empty);
            ReportingInterval = AnsiConsole.Ask<int?>("Reporting interval (ri) [optional]", ReportingInterval);
            DomainName = AnsiConsole.Ask("Domain name [optional]", DomainName ?? string.Empty);
            var apiUrl = AnsiConsole.Ask<string>("DNS provider API endpoint [optional]", DnsApiUrl?.ToString() ?? string.Empty);
            DnsApiUrl = string.IsNullOrWhiteSpace(apiUrl) ? DnsApiUrl : new Uri(apiUrl);
            Publish = AnsiConsole.Confirm("Publish record via DNS provider?", Publish.IsPresent);
        }
    }
}
