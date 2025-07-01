using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Net.Http;
using DomainDetective;
using Spectre.Console;

namespace DomainDetective.PowerShell {
    /// <summary>Builds a DMARC record string.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Create a DMARC record.</summary>
    ///   <code>New-DmarcRecord -Policy reject -AggregateUri mailto:reports@example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.New, "DmarcRecord")]
    [OutputType(typeof(string))]
    public sealed class CmdletNewDmarcRecord : PSCmdlet {
        /// <param name="Policy">Main DMARC policy.</param>
        [Parameter(Position = 0)]
        [ValidateSet("none", "quarantine", "reject")]
        public string Policy { get; set; }

        /// <param name="SubPolicy">Policy applied to subdomains.</param>
        [Parameter]
        [ValidateSet("none", "quarantine", "reject")]
        public string SubPolicy { get; set; }

        /// <param name="AggregateUri">Aggregate report URI(s).</param>
        [Parameter]
        public string AggregateUri { get; set; }

        /// <param name="ForensicUri">Forensic report URI(s).</param>
        [Parameter]
        public string ForensicUri { get; set; }

        /// <param name="Percent">Percentage of mail subjected to the policy.</param>
        [Parameter]
        [ValidateRange(0, 100)]
        public int? Percent { get; set; }

        /// <param name="DkimAlignment">DKIM alignment mode.</param>
        [Parameter]
        [ValidateSet("r", "s")]
        public string DkimAlignment { get; set; }

        /// <param name="SpfAlignment">SPF alignment mode.</param>
        [Parameter]
        [ValidateSet("r", "s")]
        public string SpfAlignment { get; set; }

        /// <param name="FailureOptions">Failure reporting options.</param>
        [Parameter]
        public string FailureOptions { get; set; }

        /// <param name="ReportingInterval">Reporting interval in seconds.</param>
        [Parameter]
        public int? ReportingInterval { get; set; }

        /// <param name="DomainName">Domain name for publishing.</param>
        [Parameter]
        public string DomainName { get; set; }

        /// <param name="DnsApiUrl">DNS provider API endpoint.</param>
        [Parameter]
        public Uri DnsApiUrl { get; set; }

        /// <param name="Publish">Publish the record via DNS provider.</param>
        [Parameter]
        public SwitchParameter Publish { get; set; }

        /// <param name="StepByStep">Prompt step by step for all options.</param>
        [Parameter]
        public SwitchParameter StepByStep { get; set; }

        protected override void BeginProcessing() {
            if (StepByStep) {
                PromptForParameters();
            }
        }

        /// <summary>Outputs the composed DMARC record.</summary>
        protected override void EndProcessing() {
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
                PublishRecord(record);
            }
        }

        private void PublishRecord(string record) {
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
                var response = client.PostAsync(DnsApiUrl, new FormUrlEncodedContent(data)).GetAwaiter().GetResult();
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
