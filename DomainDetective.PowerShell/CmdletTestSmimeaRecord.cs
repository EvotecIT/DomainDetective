using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates SMIMEA records for the given email address.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check SMIMEA record.</summary>
    ///   <code>Test-DDDnsSmimeaRecord -EmailAddress user@example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsSmimeaRecord", DefaultParameterSetName = "Email")]
[Alias("Test-DnsSmimea")]
    public sealed class CmdletTestSmimeaRecord : ExportableAsyncPSCmdlet {
        /// <summary>Email address to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Email")]
        [ValidateNotNullOrEmpty]
        public string EmailAddress = string.Empty;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "Email")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var psLogger = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            psLogger.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            ApplyExecutionOptions(_healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying SMIMEA record for {0}", EmailAddress);
            await _healthCheck.VerifySMIMEA(EmailAddress);
            var output = DomainDetective.Views.Converters.Convert(_healthCheck.SmimeaAnalysis);
            WriteObject(output);
            if (IsExportRequested()) {
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { output },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        "smimea",
                        DomainDetective.Reports.ReportScope.Normal,
                        $"SMIMEA Report - {EmailAddress}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDDnsSmimeaRecord");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"SMIMEA export failed: {ex.Message}");
                }
            }
        }
    }
}

