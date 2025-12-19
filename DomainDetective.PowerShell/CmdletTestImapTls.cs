using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks TLS configuration for a specific IMAP host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Test IMAP TLS.</summary>
    ///   <code>Test-DDEmailImapTls -HostName mail.example.com -Port 993</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailImapTls", DefaultParameterSetName = "ServerName")]
    [Alias("Test-EmailImapTls", "Test-ImapTls")]
    public sealed class CmdletTestImapTls : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>IMAP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName = string.Empty;

        /// <summary>IMAP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 143;

        /// <summary>Output certificate chain information.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

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
            _logger.WriteVerbose("Checking IMAP TLS for {0}:{1}", HostName, Port);
            await _healthCheck.CheckImapTlsHost(HostName, Port);
            _healthCheck.ImapTlsAnalysis.Subject = HostName;
            var analysis = _healthCheck.ImapTlsAnalysis;
            var view = DomainDetective.Views.Converters.Convert(analysis);
            var result = analysis.ServerResults[$"{HostName}:{Port}"];
            WriteObject(view);
            if (ShowChain && result.Chain.Count > 0) {
                WriteObject(result.Chain, true);
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
                            titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? $"IMAP TLS — {HostName}:{Port}" : ExportDefaults.NarrativeTitle,
                            summaryColumnCap: ExportDefaults.SummaryColumnCap,
                            headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                            footerLogoSizePx: ExportDefaults.FooterLogoSizePx);
                        if (OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser) TryOpenReport(outPath);
                    } catch (System.Exception ex) {
                        WriteWarning($"IMAP TLS export failed: {ex.Message}");
                    }
                } else {
                    await ExportNotImplementedAsync("Test-DDEmailImapTls");
                }
                return;
            }
        }
    }
}

