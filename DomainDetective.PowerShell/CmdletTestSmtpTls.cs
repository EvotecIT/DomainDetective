using System.Management.Automation;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks TLS configuration for a specific SMTP host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Test mail server TLS.</summary>
    ///   <code>Test-DDEmailSmtpTls -HostName mail.example.com -Port 587</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSmtpTls", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSmtpTls")]
    public sealed class CmdletTestSmtpTls : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName = string.Empty;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        /// <summary>Output certificate chain information.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Return the full analysis object (map of all servers) instead of a single server's details.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FullResponse;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking SMTP TLS for {0}:{1}", HostName, Port);
            await _healthCheck.CheckSmtpTlsHost(HostName, Port);
            _healthCheck.SmtpTlsAnalysis.Subject = HostName;
            var analysis = _healthCheck.SmtpTlsAnalysis;
            var view = DomainDetective.Views.Converters.Convert(analysis);
            // View-by-default design: exposes full Raw analysis on view.Raw
            WriteObject(view);
            if (ShowChain) {
                if (analysis.ServerResults != null && analysis.ServerResults.TryGetValue($"{HostName}:{Port}", out var tls) && tls.Chain.Count > 0) {
                    WriteObject(tls.Chain, true);
                }
            }
            if (IsExportRequested()) {
                var fmt = (ExportFormat != null && ExportFormat.Length > 0) ? ExportFormat[0] : ExportDefaults.Format;
                if (fmt == DomainDetective.Reports.ReportFormat.Word) {
                    var key = $"{HostName}-{Port}";
                    var outPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(ExportPath, ExportDefaults.OutputDirectory, key, fmt);
                    try {
                        DomainDetective.Reports.Office.WordCompositionReport.Generate(
                            outPath,
                            new System.Collections.Generic.List<object> { view },
                            DomainDetective.Reports.ReportScope.Normal,
                            showInfoFindings: true,
                            narrativePlacement: ExportDefaults.NarrativePlacement,
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"SMTP TLS — {HostName}:{Port}" : ExportDefaults.NarrativeTitle,
                            summaryColumnCap: ExportDefaults.SummaryColumnCap);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"SMTP TLS export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDEmailSmtpTls");
                }
                return;
            }
        }
    }
}
