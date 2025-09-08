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
    public sealed class CmdletGetFlattenedSpfIp : AsyncPSCmdlet {
        /// <para>Domain to query.</para>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <para>DNS server used for queries.</para>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>Optional SPF record used for testing to avoid DNS lookups.</para>
        [Parameter(Mandatory = false)]
        public string TestSpfRecord = string.Empty;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>
        /// Initializes the SPF analyzer and logging infrastructure.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(
                _logger,
                this.WriteVerbose,
                this.WriteWarning,
                this.WriteDebug,
                this.WriteError,
                this.WriteProgress,
                this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();

            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            if (!string.IsNullOrEmpty(TestSpfRecord)) {
                _healthCheck.SpfAnalysis.TestSpfRecords[DomainName] = TestSpfRecord;
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Performs SPF verification and outputs flattened IP analysis.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Flattening SPF IPs for domain: {0}", DomainName);
            if (!string.IsNullOrEmpty(TestSpfRecord)) {
                await _healthCheck.CheckSPF(TestSpfRecord);
            } else {
                await _healthCheck.VerifySPF(DomainName);
            }
            var analysis = await _healthCheck.SpfAnalysis.GetFlattenedIpAnalysis(DomainName, _logger);
            var view = DomainDetective.Views.Converters.Convert(analysis);
            WriteObject(view);
        }
    }
}
