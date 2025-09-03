using System.Management.Automation;
using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>Sets global export defaults for DomainDetective reports.</summary>
    [Cmdlet(VerbsCommon.Set, "DDExportOptions")]
    [Alias("Set-ExportOptions")] // convenience alias
    public sealed class CmdletSetExportOptions : PSCmdlet {
        /// <summary>Default format for exports.</summary>
        [Parameter(Mandatory = false)]
        public ReportFormat? DefaultFormat { get; set; }

        /// <summary>Default output directory for exported reports.</summary>
        [Parameter(Mandatory = false)]
        public string? OutputDirectory { get; set; }

        /// <summary>Default artifacts directory (for scan.json, metrics.json, progress.jsonl).</summary>
        [Parameter(Mandatory = false)]
        public string? ArtifactsDirectory { get; set; }

        /// <summary>Open reports after generation (HTML in browser, others via shell).</summary>
        [Parameter(Mandatory = false)]
        [Alias("OpenReport")]
        public SwitchParameter OpenInBrowser { get; set; }

        /// <summary>Emit artifacts (scan.json, metrics.json, progress.jsonl) by default.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Artifacts { get; set; }

        /// <summary>Disable artifact emission by default.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter NoArtifacts { get; set; }

        /// <summary>Reset export defaults to built-in values.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Reset { get; set; }

        protected override void ProcessRecord() {
            if (Reset) {
                ExportDefaults.Format = ReportFormat.Html;
                ExportDefaults.OpenInBrowser = true;
                ExportDefaults.OutputDirectory = string.Empty;
                ExportDefaults.EmitArtifacts = false;
                WriteVerbose("Export defaults reset to built-in values.");
                return;
            }

            if (DefaultFormat.HasValue) {
                ExportDefaults.Format = DefaultFormat.Value;
                WriteVerbose($"Default export format set to {ExportDefaults.Format}.");
            }

            if (this.MyInvocation.BoundParameters.ContainsKey(nameof(OpenInBrowser))) {
                ExportDefaults.OpenInBrowser = OpenInBrowser.IsPresent;
                WriteVerbose($"OpenInBrowser set to {ExportDefaults.OpenInBrowser}.");
            }

            if (!string.IsNullOrWhiteSpace(OutputDirectory)) {
                ExportDefaults.OutputDirectory = OutputDirectory!;
                WriteVerbose($"Default export directory set to {ExportDefaults.OutputDirectory}.");
            }
            if (!string.IsNullOrWhiteSpace(ArtifactsDirectory)) {
                ExportDefaults.ArtifactsDirectory = ArtifactsDirectory!;
                WriteVerbose($"Default artifacts directory set to {ExportDefaults.ArtifactsDirectory}.");
            }

            if (this.MyInvocation.BoundParameters.ContainsKey(nameof(Artifacts))) {
                ExportDefaults.EmitArtifacts = Artifacts.IsPresent;
                WriteVerbose($"Artifacts default set to {ExportDefaults.EmitArtifacts}.");
            }
            if (this.MyInvocation.BoundParameters.ContainsKey(nameof(NoArtifacts))) {
                ExportDefaults.EmitArtifacts = !NoArtifacts.IsPresent;
                WriteVerbose($"Artifacts default set to {ExportDefaults.EmitArtifacts}.");
            }
        }
    }
}
