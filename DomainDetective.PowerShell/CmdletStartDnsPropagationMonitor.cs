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
    ///   <code>Start-DDDnsPropagationMonitor -DomainName example.com -RecordType A -WebhookUrl https://example.com/webhook</code>
    /// </example>
    [Cmdlet(
        VerbsLifecycle.Start,
        "DDDnsPropagationMonitor",
        SupportsShouldProcess = false,
        DefaultParameterSetName = "File")]
    [Alias("Start-DnsPropagationMonitor")]
    public sealed class CmdletStartDnsPropagationMonitor : AsyncPSCmdlet {
        /// <summary>Domain to monitor.</summary>
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 0, ParameterSetName = "Custom")]
        [ValidateNotNullOrEmpty]
        public string DomainName;

        /// <summary>DNS record type.</summary>
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "File")]
        [Parameter(Mandatory = true, Position = 1, ParameterSetName = "Custom")]
        public DnsRecordType RecordType;

        /// <summary>
        /// Path to JSON file with DNS servers. If omitted the file
        /// <c>Data/DNS/PublicDNS.json</c> in the module directory is used when present.
        /// </summary>
        [Parameter(Mandatory = false, ParameterSetName = "File")]
        public string? ServersFile;

        /// <summary>One or more custom DNS servers.</summary>
        [Parameter(Mandatory = false, ParameterSetName = "Custom")]
        public string[] DnsServer = Array.Empty<string>();

        /// <summary>Filter builtin servers by country.</summary>
        [Parameter(Mandatory = false)]
        public CountryId? Country;

        /// <summary>Filter builtin servers by location.</summary>
        [Parameter(Mandatory = false)]
        public LocationId? Location;

        /// <summary>Polling interval in seconds.</summary>
        [Parameter(Mandatory = false)]
        public int IntervalSeconds = 300;

        /// <summary>Webhook URL for notifications.</summary>
        [Parameter(Mandatory = false)]
        public string? WebhookUrl;

        /// <summary>Maximum concurrent DNS queries.</summary>
        [Parameter(Mandatory = false)]
        public int MaxParallelism = 0;

        private readonly DnsPropagationMonitor _monitor = new();

        /// <summary>
        /// Configures and starts the DNS propagation monitor.
        /// </summary>
        /// <returns>A completed task.</returns>
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
                _monitor.Notifier = NotificationSenderFactory.CreateWebhook(WebhookUrl);
            }
            _monitor.Start();
            WriteObject(_monitor);
            return Task.CompletedTask;
        }
    }
}
