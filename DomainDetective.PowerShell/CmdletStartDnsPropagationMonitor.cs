using DnsClientX;
using DomainDetective.Monitoring;
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

        /// <param name="ServersFile">Path to JSON file with DNS servers.</param>
        [Parameter(Mandatory = false, ParameterSetName = "File")]
        public string? ServersFile;

        /// <param name="DnsServer">One or more custom DNS servers.</param>
        [Parameter(Mandatory = false, ParameterSetName = "Custom")]
        public string[] DnsServer = Array.Empty<string>();

        /// <param name="Country">Filter builtin servers by country.</param>
        [Parameter(Mandatory = false)]
        public string? Country;

        /// <param name="Location">Filter builtin servers by location.</param>
        [Parameter(Mandatory = false)]
        public string? Location;

        /// <param name="IntervalSeconds">Polling interval in seconds.</param>
        [Parameter(Mandatory = false)]
        public int IntervalSeconds = 300;

        /// <param name="WebhookUrl">Webhook URL for notifications.</param>
        [Parameter(Mandatory = false)]
        public string? WebhookUrl;

        private readonly DnsPropagationMonitor _monitor = new();

        protected override Task BeginProcessingAsync() {
            _monitor.Domain = DomainName;
            _monitor.RecordType = RecordType;
            _monitor.Interval = TimeSpan.FromSeconds(IntervalSeconds);
            _monitor.Country = Country;
            _monitor.Location = Location;
            if (!string.IsNullOrWhiteSpace(ServersFile)) {
                var path = Path.IsPathRooted(ServersFile)
                    ? ServersFile
                    : Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? string.Empty, ServersFile);
                _monitor.LoadServers(path);
            } else {
                _monitor.LoadBuiltinServers();
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
