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

        /// <summary>Open HTML exports in browser by default.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter OpenInBrowser { get; set; }

        /// <summary>Reset export defaults to built-in values.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Reset { get; set; }

        protected override void ProcessRecord() {
            if (Reset) {
                ExportDefaults.Format = ReportFormat.Html;
                ExportDefaults.OpenInBrowser = true;
                ExportDefaults.OutputDirectory = string.Empty;
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
        }
    }
}
