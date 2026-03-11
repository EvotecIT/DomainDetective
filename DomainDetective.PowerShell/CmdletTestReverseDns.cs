using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates PTR records for MX hosts.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check reverse DNS configuration.</summary>
    ///   <code>Test-DDDnsReverseDns -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsReverseDns", DefaultParameterSetName = "ServerName")]
    [Alias("Test-DnsReverseDns", "Test-ReverseDns")]
    public sealed class CmdletTestReverseDns : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to analyze.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    this.WriteVerbose,
                    this.WriteWarning,
                    this.WriteDebug,
                    this.WriteError,
                    this.WriteProgress,
                    this.WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Querying reverse DNS for domain: {0}", domain);
                await healthCheck.Verify(domain, new[] { HealthCheckType.REVERSEDNS }, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.ReverseDnsAnalysis);
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
                            $"Reverse DNS Report — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsReverseDns");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"Reverse DNS export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
