using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Runs authoritative DNS health checks (SOA serial skew, apex A/AAAA consistency).</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check authoritative DNS health.</summary>
    ///   <code>Test-DDDnsHealth -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDDnsHealth", DefaultParameterSetName = "Domain")]
    [Alias("Test-DnsHealth")]
    public sealed class CmdletTestDnsHealth : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Runs DNS health verification.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Running DNS health checks for {0}", domain);
                await healthCheck.Verify(domain, new[] { HealthCheckType.DNSHEALTH }, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DnsHealthAnalysis);
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
                            $"DNS Health Report — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsHealth");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"DNS health export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
