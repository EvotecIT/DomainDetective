using DomainDetective.Monitoring;
using System;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Starts background HTTP(S) uptime monitoring for one or more URLs.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Start monitoring two sites with webhook alerts.</summary>
    ///   <code>Start-DDUptimeMonitor -Url 'https://evotec.pl','https://evotec.xyz' -IntervalSeconds 60 -WebhookUrl 'https://example.com/webhook' -SnapshotDirectory .\Uptime</code>
    /// </example>
    [Cmdlet(VerbsLifecycle.Start, "DDUptimeMonitor")]
    [Alias("Start-UptimeMonitor")]
    public sealed class CmdletStartUptimeMonitor : AsyncPSCmdlet {
        /// <summary>One or more absolute HTTP(S) URLs to probe.</summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string[] Url { get; set; } = Array.Empty<string>();

        /// <summary>Polling interval in seconds (default 60).</summary>
        [Parameter(Mandatory = false)]
        public int IntervalSeconds { get; set; } = 60;

        /// <summary>Optional directory to write JSON snapshots per probe.</summary>
        [Parameter(Mandatory = false)]
        public string? SnapshotDirectory { get; set; }

        /// <summary>Optional webhook URL for alerts (DOWN/SLOW).</summary>
        [Parameter(Mandatory = false)]
        public string? WebhookUrl { get; set; }

        /// <summary>Slow TTFB threshold in milliseconds (default 2000ms).</summary>
        [Parameter(Mandatory = false)]
        public int SlowTtfbMs { get; set; } = 2000;

        /// <summary>Script to execute when a URL is detected DOWN (receives one argument: probe PSCustomObject).</summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock? OnDown { get; set; }

        /// <summary>Script to execute when a URL is SLOW (receives one argument: probe PSCustomObject).</summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock? OnSlow { get; set; }

        /// <summary>Script to execute when a URL is UP within thresholds (receives one argument: probe PSCustomObject).</summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock? OnUp { get; set; }

        /// <summary>Script to execute for any result (Severity: Down|Slow|Up) with probe PSCustomObject.</summary>
        [Parameter(Mandatory = false)]
        public ScriptBlock? OnAny { get; set; }

        private UptimeMonitor? _monitor;

        protected override Task BeginProcessingAsync() {
            _monitor = new UptimeMonitor(Url, TimeSpan.FromSeconds(Math.Max(1, IntervalSeconds)), SnapshotDirectory) {
                SlowTtfbMsThreshold = Math.Max(1, SlowTtfbMs)
            };
            if (!string.IsNullOrWhiteSpace(WebhookUrl)) {
                _monitor.Notifier = NotificationSenderFactory.CreateWebhook(WebhookUrl!);
            }
            // Map scriptblocks to callbacks that run in a fresh PowerShell instance.
            if (OnDown != null)  _monitor.OnDown  = (probe, ct) => InvokeScriptAsync(OnDown, probe, "Down");
            if (OnSlow != null)  _monitor.OnSlow  = (probe, ct) => InvokeScriptAsync(OnSlow, probe, "Slow");
            if (OnUp   != null)  _monitor.OnUp    = (probe, ct) => InvokeScriptAsync(OnUp,   probe, "Up");
            if (OnAny  != null)  _monitor.OnAny   = (probe, severity, ct) => InvokeScriptAsync(OnAny, probe, severity);
            _monitor.Start();
            WriteObject(_monitor);
            return Task.CompletedTask;
        }

        private static Task InvokeScriptAsync(ScriptBlock script, UptimeProbeAnalysis probe, string? severity)
        {
            // Build a simple PSObject payload for convenience
            var payload = new PSObject();
            payload.Properties.Add(new PSNoteProperty("Url", probe.Url?.ToString()));
            payload.Properties.Add(new PSNoteProperty("Success", probe.Success));
            payload.Properties.Add(new PSNoteProperty("StatusCode", probe.StatusCode));
            payload.Properties.Add(new PSNoteProperty("TtfbMilliseconds", probe.TtfbMilliseconds));
            payload.Properties.Add(new PSNoteProperty("TotalMilliseconds", probe.TotalMilliseconds));
            payload.Properties.Add(new PSNoteProperty("Headers", probe.ImportantHeaders));
            payload.Properties.Add(new PSNoteProperty("TimestampUtc", DateTimeOffset.UtcNow));
            if (!string.IsNullOrWhiteSpace(severity))
                payload.Properties.Add(new PSNoteProperty("Severity", severity));

            return Task.Run(() => {
                using (var ps = System.Management.Automation.PowerShell.Create())
                {
                    ps.AddScript(script.ToString());
                    ps.AddArgument(payload);
                    try { ps.Invoke(); } catch { /* swallow */ }
                }
            });
        }
    }
}
