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
        /// <summary>Domain to query.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        [ValidateNotNullOrEmpty]
        public string DomainName = string.Empty;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <para>How long RDAP results are cached.</para>
        [Parameter]
        public TimeSpan CacheDuration = TimeSpan.FromHours(1);

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var psLogger = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            psLogger.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            _healthCheck.RdapAnalysis.CacheDuration = CacheDuration;
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Querying RDAP for domain: {0}", DomainName);
            await _healthCheck.QueryRDAP(DomainName);
            var view = DomainDetective.Views.Converters.Convert(_healthCheck.RdapAnalysis);
            WriteObject(view);
            if (IsExportRequested()) { await ExportNotImplementedAsync(); return; }
        }
    }
}
