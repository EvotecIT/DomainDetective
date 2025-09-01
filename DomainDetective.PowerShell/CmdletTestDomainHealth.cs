using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;

using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
namespace DomainDetective.PowerShell {
    /// <summary>Runs multiple domain health checks and returns the results.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Perform a full health test.</summary>
    ///   <code>Test-DDDomainOverallHealth -DomainName example.com -Verbose</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDomainOverallHealth", DefaultParameterSetName = "ServerName")]
[Alias("Test-DomainHealth")]
    [OutputType(typeof(DomainHealthCheck))]
    public sealed class CmdletTestDomainHealth : ExportableAsyncPSCmdlet {
        /// <summary>Domain to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Specific tests to run.</summary>
        [Parameter(Mandatory = false)]
        public HealthCheckType[]? HealthCheckType;

        /// <summary>DKIM selectors used when testing DKIM.</summary>
        [Parameter(Mandatory = false)]
        public string[]? DkimSelectors;

        /// <summary>Service types to check for DANE. HTTPS (port 443) is queried by default.</summary>
        [Parameter(Mandatory = false)]
        public ServiceType[]? DaneServiceType;

        /// <summary>Custom ports to check for DANE.</summary>
        [Parameter(Mandatory = false)]
        public int[]? DanePorts;

        /// <summary>Protected brand terms for typosquatting analysis.</summary>
        [Parameter(Mandatory = false)]
        public string[]? BrandKeyword;
        
        /// <summary>Return the raw DomainHealthCheck object (includes a Summary property).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Raw { get; set; }

        /// <summary>Return only a condensed DomainSummary.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter Summary { get; set; }
        
        /// <summary>Port scan profiles to use.</summary>
        [Parameter(Mandatory = false)]
        public PortScanProfile[]? PortScanProfile;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
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
            if (BrandKeyword != null)
            {
                _healthCheck.TyposquattingBrandKeywords.AddRange(BrandKeyword);
            }
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying domain health for domain: {0}", DomainName);
            if (BrandKeyword != null) {
                _healthCheck.TyposquattingBrandKeywords.Clear();
                _healthCheck.TyposquattingBrandKeywords.AddRange(BrandKeyword);
            }
            await _healthCheck.Verify(DomainName, HealthCheckType, DkimSelectors, DaneServiceType, DanePorts, PortScanProfile);
            if (Summary && Raw) {
                throw new ParameterBindingException("Specify only one of -Summary or -Raw.");
            }
            if (Summary) {
                WriteObject(_healthCheck.BuildSummary());
                return;
            }
            if (Raw) {
                // Return the full object; Summary is available as a property
                WriteObject(_healthCheck);
                return;
            }
            // If export requested, generate report
            if (IsExportRequested()) {
                await GenerateReportAsync(_healthCheck);
                return;
            }

            var result = _healthCheck.FilterAnalyses(HealthCheckType);
            WriteObject(result);
        }
        private async Task GenerateReportAsync(DomainHealthCheck health) {
            var fmt = ExportFormat ?? ExportDefaults.Format;
            var path = string.IsNullOrWhiteSpace(ExportPath)
                ? GenerateDefaultPath(fmt)
                : ExportPath!;

            ReportResult result;
            switch (fmt) {
                case ReportFormat.Html:
                    WriteVerbose("Generating HTML report...");
                    var htmlReport = new DomainSecurityReport(health, DomainName);
                    htmlReport.GenerateReport(path, OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser);
                    result = new ReportResult { Success = true, FilePath = path, Format = ReportFormat.Html };
                    break;
                case ReportFormat.Json:
                    WriteVerbose("Exporting to JSON...");
                    var json = System.Text.Json.JsonSerializer.Serialize(health, DomainHealthCheck.JsonOptions);
#if NET472
                    System.IO.File.WriteAllText(path, json);
#else
                    await System.IO.File.WriteAllTextAsync(path, json);
#endif
                    result = new ReportResult { Success = true, FilePath = path, Format = ReportFormat.Json, FileSize = json.Length };
                    break;
                case ReportFormat.Pdf:
                case ReportFormat.Word:
                case ReportFormat.Excel:
                case ReportFormat.Csv:
                    WriteWarning($"{fmt} format not yet implemented (TODO)");
                    result = new ReportResult { Success = false, ErrorMessage = $"{fmt} format not yet implemented", Format = fmt };
                    break;
                default:
                    throw new ArgumentException($"Unknown export format: {fmt}");
            }

            if (result.Success) {
                WriteObject(result);
                WriteInformation($"Report generated successfully: {result.FilePath}", new string[] { "ReportGenerated" });
            } else {
                WriteError(new ErrorRecord(new InvalidOperationException(result.ErrorMessage), "ReportGenerationFailed", ErrorCategory.NotImplemented, fmt));
            }
        }
        private string GenerateDefaultPath(ReportFormat format) {
            var ts = System.DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var ext = format switch {
                ReportFormat.Html => "html",
                ReportFormat.Word => "docx",
                ReportFormat.Excel => "xlsx",
                ReportFormat.Pdf => "pdf",
                ReportFormat.Json => "json",
                ReportFormat.Csv => "csv",
                _ => "html"
            };
            var safe = (DomainName ?? "domain").Replace('.', '_');
            var file = $"{safe}_{ts}.{ext}";
            if (!string.IsNullOrWhiteSpace(ExportDefaults.OutputDirectory)) {
                try {
                    System.IO.Directory.CreateDirectory(ExportDefaults.OutputDirectory);
                    return System.IO.Path.Combine(ExportDefaults.OutputDirectory, file);
                } catch { /* ignore and fall back */ }
            }
            return file;
        }
    }
}
