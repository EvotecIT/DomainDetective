using DnsClientX;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates ARC headers from raw input.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze ARC headers from a file.</summary>
    ///   <code>Test-DDEmailArcRecord -File './headers.txt'</code>
    /// </example>
    /// <example>
    ///   <summary>Analyze ARC headers from pipeline input.</summary>
    ///   <code>Get-Content './headers.txt' -Raw | Test-DDEmailArcRecord</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailArcRecord", DefaultParameterSetName = "Text")]
[Alias("Test-EmailArc")]
    public sealed class CmdletTestArc : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <para>Raw header text.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Text", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string HeaderText { get; set; } = string.Empty;

        /// <para>Path to a file containing ARC headers.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty]
        public string File { get; set; } = string.Empty;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;
    private readonly System.Collections.Generic.List<object> _items = new();
    private readonly System.Collections.Generic.List<string> _subjects = new();
    private bool _hadUnsupportedFormats;

        /// <summary>
        /// Initializes logging and the ARC health checker.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            ApplyExecutionOptions(_healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Validates the ARC headers and writes the result to the pipeline.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            var text = ParameterSetName == "File"
                ? System.IO.File.ReadAllText(File)
                : HeaderText;
            var result = await _healthCheck.VerifyARCAsync(text, CancelToken);
            var view = DomainDetective.Views.Converters.Convert(result);
            // Prefer consistent view output across cmdlets
            WriteObject(view);
            if (!IsExportRequested()) return;
            var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format);
            var label = ParameterSetName == "File" && !string.IsNullOrWhiteSpace(File) ? System.IO.Path.GetFileName(File) : "Message";
            var wantsComposition = formats.Contains(DomainDetective.Reports.ReportFormat.Word)
                || formats.Contains(DomainDetective.Reports.ReportFormat.Html);
            if (wantsComposition) {
                _items.Add(view);
                _subjects.Add(label);
            }

            if (formats.Contains(DomainDetective.Reports.ReportFormat.Json)) {
                var outPath = ResolveOutPathForFormat(ExportPath, ExportDefaults.OutputDirectory, label, DomainDetective.Reports.ReportFormat.Json, formats);
                try {
                    var json = System.Text.Json.JsonSerializer.Serialize(result, DomainDetective.Helpers.JsonOptions.Default);
                    System.IO.File.WriteAllText(outPath, json);
                    WriteVerbose($"ARC JSON saved: {outPath}");
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } catch (System.Exception ex) {
                    WriteWarning($"ARC export failed: {ex.Message}");
                }
            }

            var hasUnsupportedFormats = formats.Any(f =>
                f != DomainDetective.Reports.ReportFormat.Word
                && f != DomainDetective.Reports.ReportFormat.Html
                && f != DomainDetective.Reports.ReportFormat.Json);
            _hadUnsupportedFormats |= hasUnsupportedFormats;

            if (!wantsComposition && !formats.Contains(DomainDetective.Reports.ReportFormat.Json)) {
                await ExportNotImplementedAsync("Test-DDEmailArcRecord");
            } else if (hasUnsupportedFormats) {
                await ExportNotImplementedAsync("Test-DDEmailArcRecord");
            }
        }

        /// <summary>
        /// Finalizes exports for Word/HTML by composing a single file.
        /// </summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var formats = GetRequestedFormatsOrDefault(ExportDefaults.Format)
                .Where(f => f == DomainDetective.Reports.ReportFormat.Word || f == DomainDetective.Reports.ReportFormat.Html)
                .ToArray();
            if (formats.Length == 0) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "arc",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            try {
                var hadUnsupportedFormats = false;
                CompositionExportHelper.WriteReports(
                    _items,
                    formats,
                    ExportPath,
                    label,
                    DomainDetective.Reports.ReportScope.Detailed,
                    $"ARC Report — {label}",
                    OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                    TryOpenReport,
                    out hadUnsupportedFormats);

                if (_hadUnsupportedFormats || hadUnsupportedFormats) {
                    return ExportNotImplementedAsync("Test-DDEmailArcRecord");
                }
            } catch (System.Exception ex) {
                WriteWarning($"ARC export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
}
}


