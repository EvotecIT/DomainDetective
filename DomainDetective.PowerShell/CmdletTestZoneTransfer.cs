using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Attempts zone transfers against authoritative name servers.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Check for open zone transfers.</summary>
    ///   <code>Test-DDDnsZoneTransfer -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsZoneTransfer", DefaultParameterSetName = "ServerName")]
    [Alias("Test-DnsZoneTransfer", "Test-ZoneTransfer")]
    public sealed class CmdletTestZoneTransfer : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var psLogger = new InternalLoggerPowerShell(
                    logger,
                    this.WriteVerbose,
                    this.WriteWarning,
                    this.WriteDebug,
                    this.WriteError,
                    this.WriteProgress,
                    this.WriteInformation);
                psLogger.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Checking zone transfer for domain: {0}", domain);
                await healthCheck.VerifyZoneTransfer(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.ZoneTransferAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    try {
                        var hadUnsupportedFormats = false;
                        CompositionExportHelper.WriteReports(
                            new System.Collections.Generic.List<object> { view },
                            GetRequestedFormatsOrDefault(ExportDefaults.Format),
                            ExportPath,
                            domain,
                            DomainDetective.Reports.ReportScope.Normal,
                            $"Zone Transfer — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsZoneTransfer");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"Zone Transfer export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}


