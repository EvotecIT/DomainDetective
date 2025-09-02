using System.Management.Automation;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective.PowerShell {
    /// <summary>Runs a static (non-browser) web scan for a URL.</summary>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebStaticScan", DefaultParameterSetName = "Url")]
    [Alias("Test-WebStaticScan")]
    public sealed class CmdletTestWebStaticScan : ExportableAsyncPSCmdlet {
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        public string Url;

        [Parameter(Mandatory = false)]
        public int MaxSeconds = 30;

        [Parameter(Mandatory = false)]
        public int MaxResources = 300;

        private InternalLogger _logger;
        private DomainHealthCheck _healthCheck;

        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        protected override async Task ProcessRecordAsync() {
            _healthCheck.WebStaticScanAnalysis.Timeout = System.TimeSpan.FromSeconds(MaxSeconds);
            _healthCheck.WebStaticScanAnalysis.MaxResources = MaxResources;
            await _healthCheck.VerifyWebStaticScan(Url);
            var ws = _healthCheck.WebStaticScanAnalysis;
            try {
                // Emit a concise tech summary similar to the CLI
                if (ws != null && ws.TechDetails != null && ws.TechDetails.Count > 0) {
                    var techs = ws.TechDetails
                        .GroupBy(t => t.Name, System.StringComparer.OrdinalIgnoreCase)
                        .Select(g => {
                            var first = g.First();
                            return new { Name = g.Key, Cat = first.Category.ToString(), Src = first.SourceKind.ToString(), Ver = first.Version, Conf = first.Confidence };
                        })
                        .OrderBy(x => x.Name)
                        .Take(8)
                        .ToArray();
                    if (techs.Length > 0) {
                        var items = techs.Select(t => string.IsNullOrWhiteSpace(t.Ver)
                            ? $"{t.Name} ({t.Cat}, {t.Src}, c{t.Conf})"
                            : $"{t.Name} {t.Ver} ({t.Cat}, {t.Src}, c{t.Conf})");
                        WriteInformation(string.Join("; ", items), new string[] { "DD", "WebStaticScan", "Tech" });
                    }
                    var third = ws.Hosts.Values.Where(h => !h.FirstParty)
                        .OrderByDescending(h => h.Bytes)
                        .Take(3)
                        .Select(h => h.Host)
                        .ToArray();
                    if (third.Length > 0) {
                        WriteInformation("Top Third-Party: " + string.Join(", ", third), new string[] { "DD", "WebStaticScan", "Hosts" });
                    }
                    var reqTotal = ws.Requests.Count;
                    if (reqTotal > 0) {
                        int https = 0; foreach (var r in ws.Requests) { try { var u = new System.Uri(r.FinalUrl ?? r.Url); if (u.Scheme == "https") https++; } catch { } }
                        var pct = (int)System.Math.Round(100.0 * https / reqTotal);
                        WriteInformation($"HTTPS: {pct}% of {reqTotal} resources", new string[] { "DD", "WebStaticScan", "HTTPS" });
                    }
                }
            } catch { }

            var view = DomainDetective.Views.Converters.Convert(ws);
            WriteObject(view);
        }
    }
}
