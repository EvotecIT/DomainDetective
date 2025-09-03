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
        // Reserved for future: Theme, Template, etc.
    }
}
