using System.Management.Automation;
using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>Sets global export defaults for DomainDetective reports.</summary>
    [Cmdlet(VerbsCommon.Set, "DDExportOptions")]
    [Alias("Set-ExportOptions")] // convenience alias
public sealed class CmdletSetExportOptions : PSCmdlet {
        // Logo size bounds: below 8px becomes unreadable; above 512px can distort Word layouts.
        private const int MinLogoSizePx = 8;
        private const int MaxLogoSizePx = 512;
        private const int MinSummaryColumns = 1;
        private const int MaxSummaryColumns = 12;

        /// <summary>Default format for exports.</summary>
        [Parameter(Mandatory = false)]
        [ValidateSet("Html","Json","Word","Excel","Markdown","MarkdownHtml", IgnoreCase = true)]
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

        /// <summary>Header logo height in pixels (optional).</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(MinLogoSizePx, MaxLogoSizePx)]
        public int? HeaderLogoSizePx { get; set; }

        /// <summary>Footer logo height in pixels (optional).</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(MinLogoSizePx, MaxLogoSizePx)]
        public int? FooterLogoSizePx { get; set; }

        /// <summary>Header text (optional; shown in Word header if provided).</summary>
        [Parameter(Mandatory = false)]
        public string? HeaderText { get; set; }

        /// <summary>Footer text (optional; shown in Word footer if provided).</summary>
        [Parameter(Mandatory = false)]
        public string? FooterText { get; set; }

        /// <summary>Watermark text (optional; applied to sections).</summary>
        [Parameter(Mandatory = false)]
        public string? WatermarkText { get; set; }

        /// <summary>Max status columns in Word executive summary tables.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(MinSummaryColumns, MaxSummaryColumns)]
        public int? SummaryColumnCap { get; set; }

        /// <summary>Company name for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyName { get; set; }

        /// <summary>Company address for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyAddress { get; set; }

        /// <summary>Company year for custom document properties.</summary>
        [Parameter(Mandatory = false)]
        public string? CompanyYear { get; set; }

        // Narrative metadata overrides
        /// <summary>Override the report Title.</summary>
        [Parameter(Mandatory = false)]
        public string? Title { get; set; }
        /// <summary>Override the report Subject/Description.</summary>
        [Parameter(Mandatory = false)]
        public string? Subject { get; set; }
        /// <summary>Override the report Category.</summary>
        [Parameter(Mandatory = false)]
        public string? Category { get; set; }
        /// <summary>Override the report Keywords (comma-separated).</summary>
        [Parameter(Mandatory = false)]
        public string? Keywords { get; set; }
        /// <summary>Override the report Creator/Author.</summary>
        [Parameter(Mandatory = false)]
        public string? Creator { get; set; }

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

        /// <summary>Default narrative placement for reports.</summary>
        [Parameter(Mandatory = false)]
        public NarrativePlacement? NarrativePlacement { get; set; }

        /// <summary>Applies the specified export option changes.</summary>
        protected override void ProcessRecord() {
            if (Reset) {
                ExportDefaults.Format = ReportFormat.Html;
                ExportDefaults.OpenInBrowser = true;
                ExportDefaults.OutputDirectory = string.Empty;
                ExportDefaults.EmitArtifacts = false;
                ExportDefaults.ArtifactsDirectory = string.Empty;
                ExportDefaults.NarrativePlacement = DomainDetective.Reports.NarrativePlacement.Auto;
                ExportDefaults.LogoPath = string.Empty;
                ExportDefaults.HeaderLogoSizePx = null;
                ExportDefaults.FooterLogoSizePx = null;
                ExportDefaults.HeaderText = string.Empty;
                ExportDefaults.FooterText = string.Empty;
                ExportDefaults.WatermarkText = string.Empty;
                ExportDefaults.SummaryColumnCap = 4;
                ExportDefaults.CompanyName = string.Empty;
                ExportDefaults.CompanyAddress = string.Empty;
                ExportDefaults.CompanyYear = string.Empty;
                ExportDefaults.NarrativeTitle = string.Empty;
                ExportDefaults.NarrativeSubject = string.Empty;
                ExportDefaults.NarrativeCategory = string.Empty;
                ExportDefaults.NarrativeKeywords = string.Empty;
                ExportDefaults.NarrativeCreator = string.Empty;
                WriteVerbose("Export defaults reset to built-in values.");
                return;
            }

            if (DefaultFormat.HasValue) {
                ValidateDefaultFormat(DefaultFormat.Value);
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
            if (NarrativePlacement.HasValue) {
                ExportDefaults.NarrativePlacement = NarrativePlacement.Value;
                WriteVerbose($"Default narrative placement set to {ExportDefaults.NarrativePlacement}.");
            }
            if (!string.IsNullOrWhiteSpace(LogoPath)) {
                ExportDefaults.LogoPath = LogoPath!;
                WriteVerbose($"LogoPath set to {ExportDefaults.LogoPath}.");
            }
            if (HeaderLogoSizePx.HasValue) {
                ExportDefaults.HeaderLogoSizePx = HeaderLogoSizePx.Value;
                WriteVerbose($"HeaderLogoSizePx set to {ExportDefaults.HeaderLogoSizePx}.");
            }
            if (FooterLogoSizePx.HasValue) {
                ExportDefaults.FooterLogoSizePx = FooterLogoSizePx.Value;
                WriteVerbose($"FooterLogoSizePx set to {ExportDefaults.FooterLogoSizePx}.");
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
            if (SummaryColumnCap.HasValue) {
                ExportDefaults.SummaryColumnCap = SummaryColumnCap.Value;
                WriteVerbose($"SummaryColumnCap set to {ExportDefaults.SummaryColumnCap}.");
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

            // Narrative overrides
            if (!string.IsNullOrWhiteSpace(Title)) {
                ExportDefaults.NarrativeTitle = Title!;
                WriteVerbose($"Narrative Title set to '{ExportDefaults.NarrativeTitle}'.");
            }
            if (!string.IsNullOrWhiteSpace(Subject)) {
                ExportDefaults.NarrativeSubject = Subject!;
                WriteVerbose($"Narrative Subject set to '{ExportDefaults.NarrativeSubject}'.");
            }
            if (!string.IsNullOrWhiteSpace(Category)) {
                ExportDefaults.NarrativeCategory = Category!;
                WriteVerbose($"Narrative Category set to '{ExportDefaults.NarrativeCategory}'.");
            }
            if (!string.IsNullOrWhiteSpace(Keywords)) {
                ExportDefaults.NarrativeKeywords = Keywords!;
                WriteVerbose($"Narrative Keywords set.");
            }
            if (!string.IsNullOrWhiteSpace(Creator)) {
                ExportDefaults.NarrativeCreator = Creator!;
                WriteVerbose($"Narrative Creator set to '{ExportDefaults.NarrativeCreator}'.");
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

        internal static void ValidateDefaultFormat(ReportFormat format)
        {
            if (format == ReportFormat.Pdf) {
                throw new System.ArgumentException("PDF report generation is not currently shipped in DomainDetective. Generate Word output and convert it with OfficeIMO PDF support when that package path is available.", nameof(DefaultFormat));
            }
        }
    }
}
