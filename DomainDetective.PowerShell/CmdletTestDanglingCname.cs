using DnsClientX;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks for dangling CNAME records on a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Detect unclaimed CNAMEs.</summary>
    ///   <code>Test-DDDnsDanglingCname -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsDanglingCname", DefaultParameterSetName = "ServerName")]
[Alias("Test-DnsDanglingCname")]
    public sealed class CmdletTestDanglingCname : ExportableAsyncPSCmdlet {
        /// <para>Domain(s) to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string[] DomainName = Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>
        /// Checks for dangling CNAME entries on the domain.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
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

                logger.WriteVerbose("Checking dangling CNAME for domain: {0}", domain);
                await healthCheck.Verify(domain, new[] { HealthCheckType.DANGLINGCNAME }, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DanglingCnameAnalysis);
                WriteObject(view);
                if (IsExportRequested()) {
                    await ExportNotImplementedAsync();
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}



