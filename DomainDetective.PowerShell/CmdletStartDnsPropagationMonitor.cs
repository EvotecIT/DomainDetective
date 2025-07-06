using DnsClientX;
using DomainDetective.Monitoring;
using DomainDetective;
using System;
using System.IO;
using System.Management.Automation;
using System.Reflection;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Starts background monitoring of DNS propagation.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Start monitoring an A record.</summary>
    ///   <code>Start-DnsPropagationMonitor -DomainName example.com -RecordType A -WebhookUrl https://example.com/webhook</code>
    /// </example>
    [Cmdlet(
        VerbsLifecycle.Start,
        "DnsPropagationMonitor",
        SupportsShouldProcess = false,
        DefaultParameterSetName = "File")]
    public sealed class CmdletStartDnsPropagationMonitor : AsyncPSCmdlet {
        /// <param name="DomainName">Domain to monitor.</param>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Custom")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <param name="RecordType">DNS record type.</param>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Custom")]
        public DnsRecordType RecordType;

        /// <param name="ServersFile">Path to JSON file with DNS servers. If omitted the file
        /// <c>Data/DNS/PublicDNS.json</c> in the module directory is used when present.</param>
        [Parameter(Mandatory = false, ParameterSetName = "File")]
        public string? ServersFile;

        /// <param name="DnsServer">One or more custom DNS servers.</param>
        [Parameter(Mandatory = false, ParameterSetName = "Custom")]
        public string[] DnsServer = Array.Empty<string>();

        /// <param name="Country">Filter builtin servers by country.</param>
        [Parameter(Mandatory = false)]
        public CountryId? Country;

        /// <param name="Location">Filter builtin servers by location.</param>
        [Parameter(Mandatory = false)]
        public LocationId? Location;

        /// <param name="IntervalSeconds">Polling interval in seconds.</param>
        [Parameter(Mandatory = false)]
        public int IntervalSeconds = 300;

        /// <param name="WebhookUrl">Webhook URL for notifications.</param>
        [Parameter(Mandatory = false)]
        public string? WebhookUrl;

        /// <param name="MaxParallelism">Maximum concurrent DNS queries.</param>
        [Parameter(Mandatory = false)]
        public int MaxParallelism = 0;

        private readonly DnsPropagationMonitor _monitor = new();

        protected override Task BeginProcessingAsync() {
            _monitor.Domain = DomainName;
            _monitor.RecordType = RecordType;
            _monitor.Interval = TimeSpan.FromSeconds(IntervalSeconds);
            _monitor.Country = Country;
            _monitor.Location = Location;
            _monitor.MaxParallelism = MaxParallelism;
            var moduleBase = this.MyInvocation.MyCommand.Module?.ModuleBase
                ?? Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
                ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(ServersFile)) {
                var path = Path.IsPathRooted(ServersFile)
                    ? ServersFile
                    : Path.Combine(moduleBase, ServersFile);
                _monitor.LoadServers(path);
            } else {
                var defaultFile = Path.Combine(moduleBase, "Data", "DNS", "PublicDNS.json");
                if (File.Exists(defaultFile)) {
                    _monitor.LoadServers(defaultFile);
                } else {
                    _monitor.LoadBuiltinServers();
                }
            }
            if (ParameterSetName == "Custom") {
                foreach (var ip in DnsServer) {
                    if (System.Net.IPAddress.TryParse(ip, out var parsed)) {
                        _monitor.AddServer(new PublicDnsEntry { IPAddress = parsed, Enabled = true });
                    } else {
                        WriteWarning($"Invalid DNS server IP: {ip}");
                    }
                }
            }
            if (!string.IsNullOrWhiteSpace(WebhookUrl)) {
                _monitor.Notifier = new WebhookNotificationSender(WebhookUrl);
            }
            _monitor.Start();
            WriteObject(_monitor);
            return Task.CompletedTask;
        }
    }
}
