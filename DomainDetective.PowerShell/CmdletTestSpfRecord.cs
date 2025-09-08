using System;
using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SPF record for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SPF configuration.</summary>
    ///   <code>Test-DDEmailSpfRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSpfRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSpf")]
    public sealed class CmdletTestSpfRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        //[Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        //public SwitchParameter FullResponse;

        private InternalLogger _logger = null!;
        private DomainHealthCheck healthCheck = null!;
        private readonly System.Collections.Generic.List<object> _items = new();
        private readonly System.Collections.Generic.List<string> _subjects = new();

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            foreach (var domain in DomainName) {
                _logger.WriteVerbose("Querying SPF record for domain: {0}", domain);
                await healthCheck.VerifySPF(domain);
                var output = DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis);
                WriteObject(output);

                if (!IsExportRequested()) continue;
                var fmt = ExportFormat ?? ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word || fmt == DomainDetective.Reports.ReportFormat.Html) {
                    _items.Add(output);
                    _subjects.Add(domain);
                } else if (fmt == DomainDetective.Reports.ReportFormat.Json) {
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, domain, fmt);
                    try {
                        var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.SpfAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                        System.IO.File.WriteAllText(outPath, json);
                        WriteVerbose($"SPF JSON saved: {outPath}");
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"SPF export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                }
            }
        }

        /// <summary>
        /// Finalizes multi-domain exports for Word/HTML by composing a single file.
        /// </summary>
        protected override Task EndProcessingAsync() {
            if (_items.Count == 0) return Task.CompletedTask;
            var fmt = ExportFormat ?? ExportDefaults.Format;
            if (fmt != DomainDetective.Reports.ReportFormat.Word && fmt != DomainDetective.Reports.ReportFormat.Html) return Task.CompletedTask;

            var label = _subjects.Count switch {
                0 => "spf",
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
                        titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"SPF Report — {label}" : ExportDefaults.NarrativeTitle,
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
                WriteWarning($"SPF export failed: {ex.Message}");
            }
            return Task.CompletedTask;
        }
    }
}
