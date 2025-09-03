using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>
    /// Base cmdlet providing common -Export* parameters and helpers.
    /// </summary>
    public abstract class ExportableAsyncPSCmdlet : AsyncPSCmdlet {
        /// <summary>Desired export format.</summary>
        [Parameter(Mandatory = false)]
        public ReportFormat? ExportFormat { get; set; }

        /// <summary>Output file path for export.</summary>
        [Parameter(Mandatory = false)]
        public string? ExportPath { get; set; }

        /// <summary>Open export in browser when applicable.</summary>
        [Parameter(Mandatory = false)]
        [Alias("OpenReport")]
        public SwitchParameter OpenInBrowser { get; set; }

        /// <summary>Emit artifacts (scan.json, metrics.json, progress.jsonl).</summary>
        [Parameter(Mandatory = false)]
        [Alias("Artifacts")]
        public SwitchParameter ExportArtifacts { get; set; }

        /// <summary>Destination directory for artifacts when emitted.</summary>
        [Parameter(Mandatory = false)]
        [Alias("ArtifactsPath")]
        public string? ArtifactsDirectory { get; set; }

        protected void TryOpenReport(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try {
                var psi = new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(psi);
            } catch { }
        }

        protected bool IsExportRequested()
            => ExportFormat.HasValue
               || !string.IsNullOrWhiteSpace(ExportPath)
               || OpenInBrowser.IsPresent;

        protected Task ExportNotImplementedAsync(string? cmdletName = null) {
            var name = cmdletName ?? GetCmdletName();
            WriteWarning($"Export for {name} is not yet implemented (TODO). Use Test-DDDomainOverallHealth for full reports.");
            WriteError(new ErrorRecord(
                new System.NotImplementedException($"Export for {name} not implemented."),
                "ExportNotImplemented",
                ErrorCategory.NotImplemented,
                name));
            return Task.CompletedTask;
        }

        private string GetCmdletName() {
            var attr = (System.Management.Automation.CmdletAttribute?)System.Attribute.GetCustomAttribute(this.GetType(), typeof(System.Management.Automation.CmdletAttribute));
            if (attr != null && !string.IsNullOrEmpty(attr.VerbName) && !string.IsNullOrEmpty(attr.NounName)) {
                return $"{attr.VerbName}-{attr.NounName}";
            }
            return this.GetType().Name;
        }
    }
}
