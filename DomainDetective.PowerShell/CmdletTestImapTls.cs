using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks TLS configuration for a specific IMAP host.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Test IMAP TLS.</summary>
    ///   <code>Test-DDEmailImapTls -HostName mail.example.com -Port 993</code>
    /// </example>
    /// <example>
    ///   <summary>Test only the IPv6 path for an IMAP host.</summary>
    ///   <code>Test-DDEmailImapTls -HostName mail.example.com -Port 993 -AddressFamily IPv6</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailImapTls", DefaultParameterSetName = "ServerName")]
    [Alias("Test-EmailImapTls", "Test-ImapTls")]
    public sealed class CmdletTestImapTls : ExportableAsyncPSCmdlet {
        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false)]
        public DnsClientX.DnsEndpoint DnsEndpoint = DnsClientX.DnsEndpoint.System;
        /// <summary>IMAP host to check.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "ServerName")]
        public string HostName = string.Empty;

        /// <summary>IMAP port number.</summary>
        [Parameter(Mandatory = false, Position = 1, ParameterSetName = "ServerName")]
        public int Port = 143;

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
            _logger.WriteVerbose("Checking IMAP TLS for {0}:{1}", HostName, Port);
            var endpoint = new MailTransportEndpoint(HostName, Port) {
                ConnectAddress = ConnectAddress,
                AddressFamily = AddressFamily
            };
            await _healthCheck.CheckImapTlsHost(endpoint, CancelToken);
            _healthCheck.ImapTlsAnalysis.Subject = HostName;
            var analysis = _healthCheck.ImapTlsAnalysis;
            var view = DomainDetective.Views.Converters.Convert(analysis);
            var result = analysis.ServerResults[endpoint.Key];
            WriteObject(view);
            if (ShowChain && result.Chain.Count > 0) {
                WriteObject(result.Chain, true);
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
                        $"IMAP TLS — {HostName}:{Port}",
                        OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                        TryOpenReport,
                        out hadUnsupportedFormats);

                    if (hadUnsupportedFormats) {
                        await ExportNotImplementedAsync("Test-DDEmailImapTls");
                    }
                } catch (System.Exception ex) {
                    WriteWarning($"IMAP TLS export failed: {ex.Message}");
                }
                return;
            }
        }
    }
}


