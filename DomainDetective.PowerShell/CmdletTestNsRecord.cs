using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves NS records for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Query name servers.</summary>
    ///   <code>Test-DDDnsNsRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsNsRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsNs")]
    public sealed class CmdletTestNsRecord : ExportableAsyncPSCmdlet {
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

                logger.WriteVerbose("Querying NS record for domain: {0}", domain);
                await healthCheck.VerifyNS(domain, cancellationToken: CancelToken);
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
                            $"NS Report — {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsNsRecord");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"NS export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}


