using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>
    /// Global export defaults configurable via Set-DDExportOptions.
    /// </summary>
    public static class ExportDefaults {
        public static ReportFormat Format { get; set; } = ReportFormat.Html;
        public static bool OpenInBrowser { get; set; } = true;
        public static string OutputDirectory { get; set; } = string.Empty;
        public static bool EmitArtifacts { get; set; } = false;
        public static string ArtifactsDirectory { get; set; } = string.Empty;
        // Branding / report cosmetics
        public static string LogoPath { get; set; } = string.Empty;
        public static string HeaderText { get; set; } = string.Empty;
        public static string FooterText { get; set; } = string.Empty;
        public static string WatermarkText { get; set; } = string.Empty;
        // Company custom properties (exposed to Word reports)
        public static string CompanyName { get; set; } = string.Empty;
        public static string CompanyAddress { get; set; } = string.Empty;
        public static string CompanyYear { get; set; } = string.Empty;
        // Reserved for future: Theme, Template, etc.
    }
}
