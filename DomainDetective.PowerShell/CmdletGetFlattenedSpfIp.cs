using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Retrieves flattened SPF IP analysis for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <para>Use the <c>TestSpfRecord</c> parameter to supply an SPF record during tests.</para>
    /// <example>
    ///   <summary>Get flattened SPF IPs.</summary>
    ///   <code>Get-DDDomainFlattenedSpfIp -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "DDDomainFlattenedSpfIp", DefaultParameterSetName = "ServerName")]
    [Alias("Get-DomainFlattenedSpfIp")]
    [OutputType(typeof(FlattenedSpfResult))]
    public sealed class CmdletGetFlattenedSpfIp : ParallelAsyncPSCmdlet {
        /// <para>Domain(s) to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Optional SPF record used for testing to avoid DNS lookups.</para>
        [Parameter(Mandatory = false)]
        public string TestSpfRecord = string.Empty;

        /// <summary>
        /// Performs SPF verification and outputs flattened IP analysis.
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

                logger.WriteVerbose("Flattening SPF IPs for domain: {0}", domain);
                if (!string.IsNullOrEmpty(TestSpfRecord)) {
                    healthCheck.SpfAnalysis.TestSpfRecords[domain] = TestSpfRecord;
                    await healthCheck.CheckSPF(TestSpfRecord, cancellationToken: CancelToken);
                } else {
                    await healthCheck.VerifySPF(domain, cancellationToken: CancelToken);
                }
                var analysis = await healthCheck.SpfAnalysis.GetFlattenedIpAnalysis(domain, logger);
                var view = DomainDetective.Views.Converters.Convert(analysis);
                WriteObject(view);
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
