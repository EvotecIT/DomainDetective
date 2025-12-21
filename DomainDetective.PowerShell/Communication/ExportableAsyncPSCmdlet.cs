using System;
using System.Management.Automation;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;

namespace DomainDetective.PowerShell {
    /// <summary>
    /// Base cmdlet providing common -Export* parameters and helpers.
    /// </summary>
    public abstract class ExportableAsyncPSCmdlet : AsyncPSCmdlet {
        /// <summary>Desired export format(s). Accepts one or many values.</summary>
        [Parameter(Mandatory = false)]
        [Alias("Report")]
        [ValidateSet("Html","Json","Pdf","Word","Excel","Markdown","MarkdownHtml", IgnoreCase = true)]
        public ReportFormat[]? ExportFormat { get; set; }

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

        /// <summary>Disable parallel execution (cmdlet-level and health checks).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter DisableParallel { get; set; }

        /// <summary>Maximum number of concurrent items for cmdlet-level parallel work.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? ThrottleLimit { get; set; }

        /// <summary>Maximum concurrent health checks within a single domain run.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? MaxParallelism { get; set; }

        /// <summary>DNS resolver concurrency hint for health checks.</summary>
        [Parameter(Mandatory = false)]
        [ValidateRange(ParallelExecutionDefaults.MinParallelism, ParallelExecutionDefaults.MaxParallelism)]
        public int? DnsParallelism { get; set; }

        /// <summary>Attempts to open the specified report file.</summary>
        /// <param name="path">Path to the report.</param>
        protected void TryOpenReport(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try {
                var psi = new System.Diagnostics.ProcessStartInfo { FileName = path, UseShellExecute = true };
                System.Diagnostics.Process.Start(psi);
            } catch { }
        }

        /// <summary>Determines whether an export was requested.</summary>
        /// <returns><c>true</c> if export options were specified; otherwise, <c>false</c>.</returns>
        protected bool IsExportRequested()
            => (ExportFormat != null && ExportFormat.Length > 0)
               || !string.IsNullOrWhiteSpace(ExportPath)
               || OpenInBrowser.IsPresent;

        /// <summary>Emits a warning indicating export is not implemented.</summary>
        /// <param name="cmdletName">Name of the cmdlet requesting export.</param>
        /// <returns>A completed task.</returns>
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

        /// <summary>Returns requested formats or a single fallback format.</summary>
        protected IReadOnlyList<ReportFormat> GetRequestedFormatsOrDefault(ReportFormat fallback)
            => (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat : new[] { fallback };

        /// <summary>
        /// Computes output path for a specific format, honoring explicit file paths when multiple formats were requested.
        /// </summary>
        protected string ResolveOutPathForFormat(string? explicitPath, string? defaultOutputDirectory, string label, ReportFormat fmt, IReadOnlyList<ReportFormat>? all = null)
        {
            var fmts = all ?? GetRequestedFormatsOrDefault(fallback: fmt);
            if (!string.IsNullOrWhiteSpace(explicitPath))
            {
                try
                {
                    var p = explicitPath!;
                    var looksLikeDirectory = false;
                    if (System.IO.Directory.Exists(p)) looksLikeDirectory = true;
                    else if (p.EndsWith(System.IO.Path.DirectorySeparatorChar.ToString()) || p.EndsWith(System.IO.Path.AltDirectorySeparatorChar.ToString())) looksLikeDirectory = true;
                    else if (!System.IO.Path.HasExtension(p)) looksLikeDirectory = true;

                    if (!looksLikeDirectory && fmts.Count > 1)
                    {
                        // User provided a file path but asked for multiple formats; derive per-format paths by swapping extension.
                        var dir = System.IO.Path.GetDirectoryName(p) ?? string.Empty;
                        var name = System.IO.Path.GetFileNameWithoutExtension(p);
                        var ext = fmt switch {
                            ReportFormat.Html => ".html",
                            ReportFormat.Word => ".docx",
                            ReportFormat.Excel => ".xlsx",
                            ReportFormat.Pdf => ".pdf",
                            ReportFormat.Json => ".json",
                            ReportFormat.Markdown => ".md",
                            ReportFormat.MarkdownHtml => ".html",
                            _ => ".html"
                        };
                        var combined = System.IO.Path.Combine(string.IsNullOrEmpty(dir) ? "." : dir, name + ext);
                        try { System.IO.Directory.CreateDirectory(string.IsNullOrEmpty(dir) ? "." : dir); } catch { }
                        return combined;
                    }
                }
                catch { /* fall through */ }
            }
            return ReportPathHelper.ResolveOutputPath(explicitPath, defaultOutputDirectory, label, fmt);
        }

        /// <summary>Applies shared execution options to a health check instance.</summary>
        protected void ApplyExecutionOptions(DomainHealthCheck healthCheck) {   
            healthCheck.ExecutionOptions.EnableParallelism = !DisableParallel.IsPresent;
            if (MaxParallelism.HasValue) {
                healthCheck.ExecutionOptions.MaxParallelism = MaxParallelism.Value;
            }
            if (DnsParallelism.HasValue) {
                healthCheck.ExecutionOptions.DnsParallelism = DnsParallelism.Value;
                if (healthCheck.DnsConfiguration.SupportsResolverConcurrency) {
                    healthCheck.ResolverMaxConcurrency = DnsParallelism.Value;
                }
                if (!healthCheck.MultiResolverMaxParallelism.HasValue) {
                    healthCheck.MultiResolverMaxParallelism = DnsParallelism.Value;
                }
            }
            healthCheck.ConfigureExecution();
        }

        /// <summary>Runs the provided action over inputs with optional throttling.</summary>
        protected async Task ForEachAsync<T>(IReadOnlyList<T> items, Func<T, Task> action) {
            if (items == null || items.Count == 0) {
                return;
            }
            if (DisableParallel.IsPresent || items.Count == 1) {
                foreach (var item in items) {
                    CancelToken.ThrowIfCancellationRequested();
                    await action(item);
                }
                return;
            }

            var throttle = GetEffectiveThrottleLimit();
            WriteVerbose($"Parallel execution enabled: {items.Count} item(s), throttle {throttle}.");
            using var gate = new SemaphoreSlim(throttle, throttle);
            var tasks = new Task[items.Count];
            for (var i = 0; i < items.Count; i++) {
                var local = items[i];
                tasks[i] = Task.Run(async () => {
                    await gate.WaitAsync(CancelToken);
                    try {
                        await action(local);
                    } finally {
                        gate.Release();
                    }
                }, CancelToken);
            }
            await Task.WhenAll(tasks);
        }

        /// <summary>Returns the effective throttle limit for cmdlet-level parallelism.</summary>
        protected int GetEffectiveThrottleLimit() {
            return ParallelExecutionDefaults.GetThrottleLimit(ThrottleLimit);
        }

        /// <summary>Returns true when verbose output is enabled for this invocation.</summary>
        protected bool IsVerboseEnabled() {
            if (MyInvocation?.BoundParameters?.ContainsKey("Verbose") == true) {
                return true;
            }
            var pref = GetVariableValue("VerbosePreference");
            if (pref is ActionPreference ap) {
                return ap != ActionPreference.SilentlyContinue;
            }
            return false;
        }
    }
}
