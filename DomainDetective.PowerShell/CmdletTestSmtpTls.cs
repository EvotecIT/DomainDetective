using System.Management.Automation;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks TLS configuration for a specific SMTP host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Test mail server TLS.</summary>
    ///   <code>Test-DDEmailSmtpTls -HostName mail.example.com -Port 587</code>
    /// </example>
    /// <example>
    ///   <summary>Test a specific backend while preserving the public SMTP hostname for TLS validation.</summary>
    ///   <code>Test-DDEmailSmtpTls -HostName mail.example.com -Port 587 -ConnectAddress 192.0.2.10 -AddressFamily IPv4</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailSmtpTls", DefaultParameterSetName = "ServerName")]
[Alias("Test-EmailSmtpTls")]
    public sealed class CmdletTestSmtpTls : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>SMTP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName = string.Empty;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 25;

        /// <summary>Optional concrete address used for the TCP connection while HostName remains the TLS identity.</summary>
        [Parameter(Mandatory = false)]
        public System.Net.IPAddress? ConnectAddress;

        /// <summary>Network address family used by the connection.</summary>
        [Parameter(Mandatory = false)]
        public MailTransportAddressFamily AddressFamily = MailTransportAddressFamily.Any;

        /// <summary>Output certificate chain information.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Return the full analysis object (map of all servers) instead of a single server's details.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FullResponse;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, this.WriteVerbose, this.WriteWarning, this.WriteDebug, this.WriteError, this.WriteProgress, this.WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
            ApplyExecutionOptions(_healthCheck);
            return Task.CompletedTask;
        }

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _logger.WriteVerbose("Checking SMTP TLS for {0}:{1}", HostName, Port);
            var endpoint = new MailTransportEndpoint(HostName, Port) {
                ConnectAddress = ConnectAddress,
                AddressFamily = AddressFamily
            };
            await _healthCheck.CheckSmtpTlsHost(endpoint, CancelToken);
            _healthCheck.SmtpTlsAnalysis.Subject = HostName;
            var analysis = _healthCheck.SmtpTlsAnalysis;
            var view = DomainDetective.Views.Converters.Convert(analysis);
            // View-by-default design: exposes full Raw analysis on view.Raw
            WriteObject(FullResponse.IsPresent ? (object)analysis : view);
            if (ShowChain) {
                if (analysis.ServerResults != null && analysis.ServerResults.TryGetValue(endpoint.Key, out var tls) && tls.Chain.Count > 0) {
                    WriteObject(tls.Chain, true);
                }
            }
            if (IsExportRequested()) {
                try {
                    var hadUnsupportedFormats = false;
                    CompositionExportHelper.WriteReports(
                        new System.Collections.Generic.List<object> { view },
                        GetRequestedFormatsOrDefault(ExportDefaults.Format),
                        ExportPath,
                        $"{HostName}-{Port}",
                        DomainDetective.Reports.ReportScope.Normal,
                        $"SMTP TLS — {HostName}:{Port}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDEmailSmtpTls");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"SMTP TLS export failed: {ex.Message}");
                }
                return;
            }
        }
    }
}


