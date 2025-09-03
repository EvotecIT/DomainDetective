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
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        //[Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        //public SwitchParameter FullResponse;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

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
            _logger.WriteVerbose("Querying SPF record for domain: {0}", DomainName);
            await healthCheck.VerifySPF(DomainName);
            var output = DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis);
            WriteObject(output);
            if (IsExportRequested()) {
                var fmt = ExportFormat ?? ExportDefaults.Format;
                var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, DomainName, fmt);
                try {
                    switch (fmt) {
                        case DomainDetective.Reports.ReportFormat.Html:
                            DomainDetective.Reports.Html.SpfHtmlReport.Generate(outPath, healthCheck.SpfAnalysis, DomainName, false);
                            WriteVerbose($"SPF HTML report generated: {outPath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                            break;
                        case DomainDetective.Reports.ReportFormat.Word:
                            DomainDetective.Reports.Office.SpfWordReport.Generate(
                                outPath,
                                healthCheck.SpfAnalysis,
                                DomainName,
                                string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                                string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                                string.IsNullOrWhiteSpace(ExportDefaults.FooterText) ? null : ExportDefaults.FooterText,
                                string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText
                            );
                            WriteVerbose($"SPF Word report generated: {outPath}");
                            if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                            break;
                        case DomainDetective.Reports.ReportFormat.Json:
                            {
                                var json = System.Text.Json.JsonSerializer.Serialize(healthCheck.SpfAnalysis, DomainDetective.Helpers.JsonOptions.Default);
                                System.IO.File.WriteAllText(outPath, json);
                                WriteVerbose($"SPF JSON saved: {outPath}");
                                if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                                break;
                            }
                        default:
                            await ExportNotImplementedAsync("Test-DDEmailSpfRecord");
                            break;
                    }
                }
                catch (System.Exception ex) {
                    WriteWarning($"SPF export failed: {ex.Message}");
                }
                return;
            }
        }
    }
}
