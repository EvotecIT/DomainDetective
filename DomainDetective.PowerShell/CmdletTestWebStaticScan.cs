using System.Management.Automation;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective.PowerShell {
    /// <summary>Runs a static (non-browser) web scan for a URL.</summary>
    [Cmdlet(VerbsDiagnostic.Test, "DDWebsiteStaticScan", DefaultParameterSetName = "Url")]
    [Alias("Test-WebsiteStaticScan", "Test-WebStaticScan", "Test-DDWebStaticScan")]
    public sealed class CmdletTestWebStaticScan : ExportableAsyncPSCmdlet {
        /// <summary>Starting URL or domain to scan.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Url")]
        [ValidateNotNullOrEmpty]
        [Alias("DomainName")]
        public string Url = string.Empty;

        /// <summary>Maximum scan duration in seconds.</summary>
        [Parameter(Mandatory = false)]
        public int MaxSeconds = 30;

        /// <summary>Maximum resources to process.</summary>
        [Parameter(Mandatory = false)]
        public int MaxResources = 300;

        /// <summary>Max parallel discovery (HEAD/GET) requests; 0 defers to default.</summary>
        [Parameter(Mandatory = false)]
        public int DiscoveryConcurrency = 0;

        /// <summary>Max parallel CSS fetches/processing; 0 defers to default.</summary>
        [Parameter(Mandatory = false)]
        public int CssConcurrency = 0;

        /// <summary>Max parallel TLS probes; 0 defers to default.</summary>
        [Parameter(Mandatory = false)]
        public int TlsConcurrency = 0;

        /// <summary>Max parallel DNS/RDAP enrichments; 0 defers to default.</summary>
        [Parameter(Mandatory = false)]
        public int DnsConcurrency = 0;

        /// <summary>Respect robots.txt Disallow/Allow rules during discovery.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter RespectRobots { get; set; }

        /// <summary>Skip third-party resources (only crawl first-party).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter SkipThirdParty { get; set; }

        // Link checking controls
        /// <summary>Follow anchor links and check their status (bounded by depth/pages).</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter FollowLinks { get; set; }

        /// <summary>Maximum link depth to follow (default 0).</summary>
        [Parameter(Mandatory = false)]
        public int LinkMaxDepth { get; set; } = 0;

        /// <summary>Maximum number of link pages to check (default 100).</summary>
        [Parameter(Mandatory = false)]
        public int LinkMaxPages { get; set; } = 100;

        /// <summary>Restrict link checking to first-party only.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter LinkFirstPartyOnly { get; set; }

        /// <summary>Parallelism for link checks; 0 defers to Concurrency.</summary>
        [Parameter(Mandatory = false)]
        public int LinkConcurrency { get; set; } = 0;

        /// <summary>Link-only mode: skip static resource discovery and only check links.</summary>
        [Parameter(Mandatory = false)]
        public SwitchParameter LinkOnly { get; set; }

        private InternalLogger _logger = null!;
        private DomainHealthCheck _healthCheck = null!;

        /// <summary>Initializes logging and helper classes.</summary>
        /// <returns>A completed task.</returns>
        protected override Task BeginProcessingAsync() {
            _logger = new InternalLogger(false);
            var internalLoggerPowerShell = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
            internalLoggerPowerShell.ResetActivityIdCounter();
            _healthCheck = new DomainHealthCheck(DnsClientX.DnsEndpoint.System, _logger);
            return Task.CompletedTask;
        }

        /// <summary>Executes the static web scan and outputs results.</summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _healthCheck.WebStaticScanAnalysis.Timeout = System.TimeSpan.FromSeconds(MaxSeconds);
            _healthCheck.WebStaticScanAnalysis.MaxResources = MaxResources;
            _healthCheck.WebStaticScanAnalysis.DiscoveryConcurrency = System.Math.Max(0, DiscoveryConcurrency);
            _healthCheck.WebStaticScanAnalysis.CssConcurrency = System.Math.Max(0, CssConcurrency);
            _healthCheck.WebStaticScanAnalysis.TlsConcurrency = System.Math.Max(0, TlsConcurrency);
            _healthCheck.WebStaticScanAnalysis.DnsConcurrency = System.Math.Max(0, DnsConcurrency);
            _healthCheck.WebStaticScanAnalysis.RespectRobots = RespectRobots.IsPresent;
            _healthCheck.WebStaticScanAnalysis.SkipThirdParty = SkipThirdParty.IsPresent;
            _healthCheck.WebStaticScanAnalysis.FollowLinks = FollowLinks.IsPresent;
            _healthCheck.WebStaticScanAnalysis.LinkMaxDepth = System.Math.Max(0, LinkMaxDepth);
            _healthCheck.WebStaticScanAnalysis.LinkMaxPages = System.Math.Max(1, LinkMaxPages);
            _healthCheck.WebStaticScanAnalysis.LinkFirstPartyOnly = LinkFirstPartyOnly.IsPresent ? true : _healthCheck.WebStaticScanAnalysis.LinkFirstPartyOnly;
            _healthCheck.WebStaticScanAnalysis.LinkConcurrency = System.Math.Max(0, LinkConcurrency);
            _healthCheck.WebStaticScanAnalysis.LinkOnly = LinkOnly.IsPresent;

            // Normalize input: allow bare domain, prefer http first to capture redirects, fallback to https
            var input = (Url ?? string.Empty).Trim();
            string startUrl = input;
            bool hasScheme = false;
            try { var u = new System.Uri(input); hasScheme = u.Scheme == "http" || u.Scheme == "https"; } catch { }
            if (!hasScheme) {
                // Try http first (to observe redirects), then https if http fails
                var httpUrl = $"http://{input}";
                var httpsUrl = $"https://{input}";
                try {
                    await _healthCheck.VerifyWebStaticScan(httpUrl);
                    startUrl = httpUrl;
                } catch {
                    await _healthCheck.VerifyWebStaticScan(httpsUrl);
                    startUrl = httpsUrl;
                }
            } else {
                await _healthCheck.VerifyWebStaticScan(startUrl);
            }
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
                    // Redirect chain count for the main URL
                    try {
                        var redirects = (ws.MainHttpAnalysis?.VisitedUrls?.Count ?? 1) - 1;
                        if (redirects >= 0) {
                            string start = ws.MainHttpAnalysis?.VisitedUrls?.FirstOrDefault() ?? (Url ?? "");
                            string end = ws.MainHttpAnalysis?.VisitedUrls?.LastOrDefault() ?? start;
                            string sh, eh; try { sh = new System.Uri(start).Host; } catch { sh = start; }
                            string sl, el; try { sl = new System.Uri(start).AbsoluteUri; } catch { sl = start; }
                            try { eh = new System.Uri(end).Host; } catch { eh = end; }
                            try { el = new System.Uri(end).AbsoluteUri; } catch { el = end; }
                            WriteInformation($"Redirects: {redirects} ({sh} -> {eh})", new string[] { "DD", "WebStaticScan", "Redirects" });
                            WriteVerbose($"Redirect chain: {sl} -> {el}");
                        }
                    } catch { }
                }
            } catch { }

            var view = DomainDetective.Views.Converters.Convert(ws!);
            WriteObject(view);
        }
    }
}
