using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Checks HTTPS security headers and mixed content for a domain.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Check HTTPS security.</summary>
    ///   <code>Test-DDWebsiteSecurity -DomainName example.com</code>
    /// </example>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsiteSecurity", DefaultParameterSetName = "Domain")]
    [Alias("Test-WebsiteSecurity")]
    public sealed class CmdletTestWebsiteSecurity : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to query (host or host:port).</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Domain", ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = System.Array.Empty<string>();

        /// <summary>HTTP method to use (default: GET).</summary>
        [Parameter(Mandatory = false)]
        public HttpRequestMethod Method = HttpRequestMethod.Get;

        /// <summary>Optional Cookie header value to send.</summary>
        [Parameter(Mandatory = false)]
        public string? Cookie;

        /// <summary>Additional request headers to send. Use format: 'Header: value'.</summary>
        [Parameter(Mandatory = false)]
        public string[] RequestHeader = System.Array.Empty<string>();

        /// <summary>Optional proxy URL (e.g. http://127.0.0.1:8080).</summary>
        [Parameter(Mandatory = false)]
        public string? Proxy;

        /// <summary>Disable TLS certificate validation (unsafe; off by default).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter DisableTlsValidation;

        /// <summary>Skip response body capture (disables mixed content / insecure form action checks).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter NoBody;

        /// <summary>Runs HTTPS security checks.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            async Task ProcessDomainAsync(string domain) {
                var logger = new InternalLogger(false);
                var internalLoggerPowerShell = new InternalLoggerPowerShell(
                    logger,
                    WriteVerbose,
                    WriteWarning,
                    WriteDebug,
                    WriteError,
                    WriteProgress,
                    WriteInformation);
                internalLoggerPowerShell.ResetActivityIdCounter();
                var healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, logger);
                ApplyExecutionOptions(healthCheck);

                logger.WriteVerbose("Checking HTTPS security for {0}", domain);
                var options = new HttpRequestOptions
                {
                    Method = Method,
                    Cookie = Cookie,
                    ProxyUrl = Proxy,
                    DisableTlsValidation = DisableTlsValidation.IsPresent
                };
                if (RequestHeader != null && RequestHeader.Length > 0)
                {
                    foreach (var h in RequestHeader)
                    {
                        if (string.IsNullOrWhiteSpace(h)) continue;
                        var idx = h.IndexOf(':');
                        if (idx <= 0)
                        {
                            WriteError(new ErrorRecord(new System.ArgumentException("RequestHeader values must be in 'Header: value' format."), "InvalidHeaderFormat", ErrorCategory.InvalidArgument, h));
                            continue;
                        }
                        var name = h.Substring(0, idx).Trim();
                        var value = h.Substring(idx + 1).Trim();
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            options.Headers[name] = value;
                        }
                    }
                }

                await healthCheck.VerifyWebsiteHttps(domain, options, captureBody: !NoBody.IsPresent, cancellationToken: CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.HttpAnalysis);
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
                            $"Website Security Report - {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDWebsiteSecurity");
                        }
                    } catch (System.Exception ex) {
                        WriteWarning($"Website security export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
