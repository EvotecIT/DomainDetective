using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Queries RDAP registration information.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Query RDAP.</summary>
    ///   <code>Get-DDRdap -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "DDRdap", DefaultParameterSetName = "ServerName")]
    [Alias("Get-Rdap", "Test-Rdap")]
    public sealed class CmdletTestRdap : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>How long RDAP results are cached.</para>
        [Parameter]
        public TimeSpan CacheDuration = TimeSpan.FromHours(1);

        /// <summary>Executes the cmdlet operation.</summary>
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
                healthCheck.RdapAnalysis.CacheDuration = CacheDuration;

                logger.WriteVerbose("Querying RDAP for domain: {0}", domain);
                await healthCheck.QueryRDAP(domain, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.RdapAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync("Get-DDRdap");
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
