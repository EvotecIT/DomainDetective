using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates delegation records for a domain.</summary>
    /// <example>
    ///   <summary>Check delegation.</summary>
    ///   <code>Test-DDDnsDelegation -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsDelegation", DefaultParameterSetName = "ServerName")]
    [Alias("Test-DnsDelegation", "Test-Delegation")]
    public sealed class CmdletTestDelegation : ExportableAsyncPSCmdlet {
        /// <para>Domain(s) to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>
        /// Validates parent zone delegation for the target domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var psLogger = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                psLogger.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Checking delegation for domain: {0}", domain);
                await healthCheck.VerifyDelegation(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.NSAnalysis);
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
                            $"Delegation Report — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsDelegation");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"Delegation export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
