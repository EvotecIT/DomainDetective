using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>
    /// Global export defaults configurable via Set-DDExportOptions.
    /// </summary>
    public static class ExportDefaults {
        /// <summary>Default report format.</summary>
        public static ReportFormat Format { get; set; } = ReportFormat.Html;
        /// <summary>Open generated reports in the browser.</summary>
        public static bool OpenInBrowser { get; set; } = true;
        /// <summary>Base directory for exported reports.</summary>
        public static string OutputDirectory { get; set; } = string.Empty;
        /// <summary>Emit artifact files alongside reports.</summary>
        public static bool EmitArtifacts { get; set; } = false;
        /// <summary>Directory for emitted artifacts.</summary>
        public static string ArtifactsDirectory { get; set; } = string.Empty;
        /// <summary>Narrative text placement for reports.</summary>
        public static NarrativePlacement NarrativePlacement { get; set; } = NarrativePlacement.Auto;
        // Branding / report cosmetics
        /// <summary>Logo image path.</summary>
        public static string LogoPath { get; set; } = string.Empty;
        /// <summary>Header text.</summary>
        public static string HeaderText { get; set; } = string.Empty;
        /// <summary>Footer text.</summary>
        public static string FooterText { get; set; } = string.Empty;
        /// <summary>Watermark text.</summary>
        public static string WatermarkText { get; set; } = string.Empty;
        // Company custom properties (exposed to Word reports)
        /// <summary>Company name.</summary>
        public static string CompanyName { get; set; } = string.Empty;
        /// <summary>Company address.</summary>
        public static string CompanyAddress { get; set; } = string.Empty;
        /// <summary>Company year.</summary>
        public static string CompanyYear { get; set; } = string.Empty;
        // Reserved for future: Theme, Template, etc.
    }
}
