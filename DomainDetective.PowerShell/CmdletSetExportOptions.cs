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

        /// <summary>Logo path for header branding (optional).</summary>
        [Parameter(Mandatory = false)]
        public string? LogoPath { get; set; }

        /// <summary>Header text (optional; shown in Word header if provided).</summary>
        [Parameter(Mandatory = false)]
        public string? HeaderText { get; set; }

        /// <summary>Footer text (optional; shown in Word footer if provided).</summary>
        [Parameter(Mandatory = false)]
        public string? FooterText { get; set; }

        /// <summary>Watermark text (optional; applied to sections).</summary>
        [Parameter(Mandatory = false)]
        public string? WatermarkText { get; set; }

        /// <summary>Company name for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyName { get; set; }

        /// <summary>Company address for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyAddress { get; set; }

        /// <summary>Company year for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyYear { get; set; }

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
                ExportDefaults.ArtifactsDirectory = string.Empty;
                ExportDefaults.LogoPath = string.Empty;
                ExportDefaults.HeaderText = string.Empty;
                ExportDefaults.FooterText = string.Empty;
                ExportDefaults.WatermarkText = string.Empty;
                ExportDefaults.CompanyName = string.Empty;
                ExportDefaults.CompanyAddress = string.Empty;
                ExportDefaults.CompanyYear = string.Empty;
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
            if (!string.IsNullOrWhiteSpace(LogoPath)) {
                ExportDefaults.LogoPath = LogoPath!;
                WriteVerbose($"LogoPath set to {ExportDefaults.LogoPath}.");
            }
            if (!string.IsNullOrWhiteSpace(HeaderText)) {
                ExportDefaults.HeaderText = HeaderText!;
                WriteVerbose($"HeaderText set to {ExportDefaults.HeaderText}.");
            }
            if (!string.IsNullOrWhiteSpace(FooterText)) {
                ExportDefaults.FooterText = FooterText!;
                WriteVerbose($"FooterText set to {ExportDefaults.FooterText}.");
            }
            if (!string.IsNullOrWhiteSpace(WatermarkText)) {
                ExportDefaults.WatermarkText = WatermarkText!;
                WriteVerbose($"WatermarkText set to {ExportDefaults.WatermarkText}.");
            }
            if (!string.IsNullOrWhiteSpace(CompanyName)) {
                ExportDefaults.CompanyName = CompanyName!;
                WriteVerbose($"CompanyName set to {ExportDefaults.CompanyName}.");
            }
            if (!string.IsNullOrWhiteSpace(CompanyAddress)) {
                ExportDefaults.CompanyAddress = CompanyAddress!;
                WriteVerbose($"CompanyAddress set to {ExportDefaults.CompanyAddress}.");
            }
            if (!string.IsNullOrWhiteSpace(CompanyYear)) {
                ExportDefaults.CompanyYear = CompanyYear!;
                WriteVerbose($"CompanyYear set to {ExportDefaults.CompanyYear}.");
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
