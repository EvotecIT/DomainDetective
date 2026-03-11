using System;
using System.IO;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Analyzes DNS logs for tunneling patterns.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>Outputs a view object with full raw analysis attached at Raw.</remarks>
    /// <example>
    ///   <summary>Analyze logs.</summary>
    ///   <code>Test-DDDnsTunneling -DomainName example.com -Path ./dns.log</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsTunneling", DefaultParameterSetName = "File")]
[Alias("Test-DnsTunneling")]
    public sealed class CmdletTestDnsTunneling : ExportableAsyncPSCmdlet {
        /// <summary>Domain(s) to inspect.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        [ValidateDomainName]
        public string[] DomainName = Array.Empty<string>();

        /// <summary>Log file path.</summary>
        [Parameter(Mandatory = true, Position = 1)]
        public string Path = string.Empty;

        /// <summary>Executes the cmdlet operation.</summary>
        /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            if (!File.Exists(Path)) {
                WriteError(new ErrorRecord(new FileNotFoundException("File not found", Path), "NotFound", ErrorCategory.InvalidArgument, Path));
                return;
            }

            var lines = File.ReadAllLines(Path);
            async Task ProcessDomainAsync(string domain) {
                var healthCheck = new DomainHealthCheck();
                healthCheck.DnsTunnelingLogs = lines;
                await healthCheck.CheckDnsTunnelingAsync(domain, CancelToken);
                var view = DomainDetective.Views.Converters.Convert(healthCheck.DnsTunnelingAnalysis);
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
                            $"DNS Tunneling Report - {domain}",
                            OpenInBrowser.IsPresent || ExportDefaults.OpenInBrowser,
                            TryOpenReport,
                            out hadUnsupportedFormats);

                        if (hadUnsupportedFormats) {
                            await ExportNotImplementedAsync("Test-DDDnsTunneling");
                        }
                    } catch (Exception ex) {
                        WriteWarning($"DNS tunneling export failed: {ex.Message}");
                    }
                }
            }

            await ForEachAsync(DomainName, ProcessDomainAsync);
        }
    }
}
