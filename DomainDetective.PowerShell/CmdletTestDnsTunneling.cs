using System.IO;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Analyzes DNS logs for tunneling patterns.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze logs.</summary>
    ///   <code>Test-DnsTunneling -DomainName example.com -Path ./dns.log</code>
    /// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDDnsTunneling", DefaultParameterSetName = "File")]
[Alias("Test-DnsTunneling")]
    public sealed class CmdletTestDnsTunneling : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to inspect.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="Path">Log file path.</param>
        [Parameter(Mandatory = true, Position = 1)]
        public string Path;

        private DomainHealthCheck _hc = new();

        protected override async Task ProcessRecordAsync() {
            if (!File.Exists(Path)) {
                WriteError(new ErrorRecord(new FileNotFoundException("File not found", Path), "NotFound", ErrorCategory.InvalidArgument, Path));
                return;
            }

            var lines = File.ReadAllLines(Path);
            _hc.DnsTunnelingLogs = lines;
            await _hc.CheckDnsTunnelingAsync(DomainName, CancelToken);
            WriteObject(_hc.DnsTunnelingAnalysis);
        }
    }
}
