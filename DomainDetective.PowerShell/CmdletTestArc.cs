using DnsClientX;
using System.IO;
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
            var fmt = ExportFormat ?? ExportDefaults.Format;
            if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                _items.Add(view);
                var label = ParameterSetName == "File" && !string.IsNullOrWhiteSpace(File) ? System.IO.Path.GetFileName(File) : "Message";
                _subjects.Add(label);
            } else if (fmt == DomainDetective.Reports.ReportFormat.Json) {
                var label = ParameterSetName == "File" && !string.IsNullOrWhiteSpace(File) ? System.IO.Path.GetFileName(File) : "arc";
                var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);
                try {
                    var json = System.Text.Json.JsonSerializer.Serialize(result, DomainDetective.Helpers.JsonOptions.Default);
                    System.IO.File.WriteAllText(outPath, json);
                    WriteVerbose($"ARC JSON saved: {outPath}");
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } catch (System.Exception ex) {
                    WriteWarning($"ARC export failed: {ex.Message}");
                }
            } else {
                await ExportNotImplementedAsync("Test-DDEmailArcRecord");
            }
        }

        /// <summary>
        /// Finalizes exports for Word/HTML by composing a single file.
        /// </summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmt = ExportFormat ?? ExportDefaults.Format;
            if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "arc",
                1 => _subjects[0],
                2 => $"{_subjects[0]}+{_subjects[1]}",
                _ => $"{_subjects[0]}+{_subjects[1]}(+{_subjects.Count - 2})"
            };
            var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, label, fmt);
            try {
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    DomainDetective.Reports.Office.WordCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Detailed,
                        showInfoFindings: true,
                        narrativePlacement: ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"ARC Report — {label}" : ExportDefaults.NarrativeTitle,
                        subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                        categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                        keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                        creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        companyName: string.IsNullOrWhiteSpace(ExportDefaults.CompanyName) ? null : ExportDefaults.CompanyName,
                        companyAddress: string.IsNullOrWhiteSpace(ExportDefaults.CompanyAddress) ? null : ExportDefaults.CompanyAddress,
                        companyYear: string.IsNullOrWhiteSpace(ExportDefaults.CompanyYear) ? null : ExportDefaults.CompanyYear,
                        logoPath: string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                        headerText: string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                        watermarkText: string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText);
                    if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                } else {
                    DomainDetective.Reports.Html.HtmlCompositionReport.Generate(
                        outPath,
                        _items,
                        DomainDetective.Reports.ReportScope.Detailed,
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        ExportDefaults.NarrativePlacement,
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? null : ExportDefaults.NarrativeTitle,
                        authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                        descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);
                }
            } catch (System.Exception ex) {
                WriteWarning($"ARC export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
}
}
