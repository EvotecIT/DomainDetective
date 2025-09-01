using DnsClientX;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Validates DANE TLSA records for the given domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check DANE records.</summary>
    ///   <code>Test-DDTlsDaneRecord -DomainName example.com</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDTlsDaneRecord", DefaultParameterSetName = "ServerName")]
[Alias("Test-TlsDane")]
    public sealed class CmdletTestDaneRecord : ExportableAsyncPSCmdlet {
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>Custom ports to query.</summary>
        [Parameter(Mandatory = false, Position = 2, ParameterSetName = "ServerName")]
        public int[]? Ports;

        /// <summary>Return full analysis object.</summary>
        [Parameter(Mandatory = false, ParameterSetName = "ServerName")]
        public SwitchParameter FullResponse;

        private InternalLogger _logger;
        private DomainHealthCheck healthCheck;

        /// <summary>
        /// Configures the DANE analysis infrastructure.
        /// </summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            // Initialize the logger to be able to see verbose, warning, debug, error, progress, and information messages.
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            // initialize the health check object
            healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            return Task.CompletedTask;
        }
        /// <summary>
        /// Validates DANE TLSA records for the specified ports.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying DANE record for domain: {0}", DomainName);
            var ports = Ports != null && Ports.Length > 0 ? Ports : new[] { (int)ServiceType.SMTP };
            await healthCheck.VerifyDANE(DomainName, ports, cancellationToken: CancelToken);
            var output = DomainDetective.Views.Converters.Convert(healthCheck.DaneAnalysis);
            WriteObject(output);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
