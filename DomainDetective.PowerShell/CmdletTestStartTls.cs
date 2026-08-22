using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks SMTP STARTTLS support for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Verify STARTTLS.</summary>
    ///   <code>Test-DDEmailStartTls -DomainName example.com -Port 587</code>
    /// </example>
    /// <example>
    ///   <summary>Test STARTTLS advertisement on a specific SMTP backend and retain the logical hostname in the evidence.</summary>
    ///   <code>Test-DDEmailStartTls -HostName mail.example.com -Port 587 -ConnectAddress 192.0.2.10 -AddressFamily IPv4</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDEmailStartTls", DefaultParameterSetName = "DomainName")]
    [Alias("Test-EmailStartTls")]
    public sealed class CmdletTestStartTls : ExportableAsyncPSCmdlet {
        private const string DomainSet = "DomainName";
        private const string ServerSet = "ServerName";

        /// <summary>Domain(s) to test.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = DomainSet, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>Logical SMTP hostname to test directly.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = ServerSet)]
        [ValidateNotNullOrEmpty]
        public string HostName = string.Empty;

        /// <summary>DNS server used for queries.</summary>
        [Parameter(Mandatory = false, Position = 1)]
        public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

        /// <summary>SMTP port number.</summary>
        [Parameter(Mandatory = false)]
        public int Port = 25;

        /// <summary>Optional concrete address used for the TCP connection while HostName remains the reported logical endpoint.</summary>
        [Parameter(Mandatory = false, ParameterSetName = ServerSet)]
        public System.Net.IPAddress? ConnectAddress;

        /// <summary>Network address family used by the connection.</summary>
        [Parameter(Mandatory = false)]
        public MailTransportAddressFamily AddressFamily = MailTransportAddressFamily.Any;

        /// <summary>Return the full analysis object instead of per-server details.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FullResponse;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            if (ParameterSetName == ServerSet) {
                var logger = new InternalLogger(false);
                var loggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                loggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsEndpoint, logger);
                ApplyExecutionOptions(healthCheck);
                var endpoint = new MailTransportEndpoint(HostName, Port) {
                    ConnectAddress = ConnectAddress,
                    AddressFamily = AddressFamily
                };

                logger.WriteVerbose("Querying STARTTLS for host: {0} on port {1}", HostName, Port);
                await healthCheck.CheckStartTlsHost(endpoint, CancelToken);
                healthCheck.StartTlsAnalysis.Subject = HostName;
                var directView = DomainDetective.Views.Converters.Convert(healthCheck.StartTlsAnalysis);
                WriteObject(FullResponse.IsPresent ? (object)healthCheck.StartTlsAnalysis : directView);
                if (IsExportRequested()) {
                    try {
                        var hadUnsupportedFormats = false;
                        CompositionExportHelper.WriteReports(
                            new System.Collections.Generic.List<object> { directView },
                            GetRequestedFormatsOrDefault(ExportDefaults.Format),
                            ExportPath,
                            $"{HostName}-{Port}",
                            DomainDetective.Reports.ReportScope.Normal,
                            $"STARTTLS Report - {HostName}:{Port}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDEmailStartTls");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"STARTTLS export failed: {ex.Message}");
                    }
                }
                return;
            }

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
                healthCheck.StartTlsAnalysis.AddressFamily = AddressFamily;

                logger.WriteVerbose("Querying STARTTLS for domain: {0} on port {1}", domain, Port);
                await healthCheck.VerifySTARTTLS(domain, Port, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.StartTlsAnalysis);
                WriteObject(FullResponse.IsPresent ? (object)healthCheck.StartTlsAnalysis : view);
                if (IsExportRequested()) {
                    try {
                        var hadUnsupportedFormats = false;
                        CompositionExportHelper.WriteReports(
                            new System.Collections.Generic.List<object> { view },
                            GetRequestedFormatsOrDefault(ExportDefaults.Format),
                            ExportPath,
                            domain,
                            DomainDetective.Reports.ReportScope.Normal,
                            $"STARTTLS Report - {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDEmailStartTls");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"STARTTLS export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
