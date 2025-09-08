<#
Requires: DomainDetective module on PS 5.1/7+; optional Mailozaurr for email
#>
Import-Module DomainDetective -ErrorAction Stop

# Example: Start uptime monitoring for two sites and react inline (splatting + inline scriptblocks)
$urls = @('https://evotec.pl', 'https://evotec.xyz')

$startParams = @{
    Url               = $urls
    IntervalSeconds   = 60
    SnapshotDirectory = (Join-Path $PSScriptRoot 'UptimeSnapshots')
    WebhookUrl        = 'https://example.com/webhook'
    SlowTtfbMs        = 2000
    OnDown            = {
        param($p)
        # Inline action on DOWN: send email with Mailozaurr (optional) and write a console warning
        try {
            Import-Module Mailozaurr -ErrorAction Stop
            $subject = "Uptime DOWN: $($p.Url) [$($p.StatusCode)]"
            $body = @"
URL: $($p.Url)
Status: $($p.StatusCode)
TTFB: $($p.TtfbMilliseconds) ms
Total: $($p.TotalMilliseconds) ms
When:  $($p.TimestampUtc.ToString('u'))

Headers:
$(($p.Headers.GetEnumerator() | ForEach-Object { "{0}: {1}" -f $_.Key, $_.Value }) -join "`n")
"@
            $emailParams = @{
                Server   = 'smtp.evotec.pl'
                From     = 'monitor@evotec.pl'
                To       = 'alerts@evotec.pl'
                Subject  = $subject
                Body     = $body
                UseSsl   = $false
                Encoding = 'UTF8'
            }
            Send-EmailMessage @emailParams
        } catch {
            Write-Warning ("[DOWN][email-failed] {0} :: {1}" -f $p.Url, $_)
        }
        Write-Warning ("[DOWN] {0} status={1} ttfb={2}ms" -f $p.Url, $p.StatusCode, $p.TtfbMilliseconds)
    }
    OnSlow            = {
        param($p)
        # Inline action on SLOW: write a warning; you could also call a Slack webhook here
        Write-Warning ("[SLOW] {0} ttfb={1}ms total={2}ms" -f $p.Url, $p.TtfbMilliseconds, $p.TotalMilliseconds)
    }
    OnUp              = {
        param($p)
        # Inline action on UP (healthy + under threshold): brief note
        Write-Host ("[UP] {0} ttfb={1}ms" -f $p.Url, $p.TtfbMilliseconds)
    }
    OnAny             = {
        param($p)
        # Inline catch-all: $p.Severity is Down|Slow|Up; append a CSV log per event
        $line = '{0},{1},{2},{3},{4}' -f $p.TimestampUtc.ToString('u'), $p.Severity, $p.Url, $p.StatusCode, $p.TtfbMilliseconds
        $logPath = Join-Path $PSScriptRoot 'uptime-events.csv'
        Add-Content -Path $logPath -Value $line -Encoding UTF8
    }
}

$monitor = Start-DDUptimeMonitor @startParams

# Let it run for 5 minutes in this demo, then stop (press Ctrl+C to keep running)
Start-Sleep -Seconds 300

$stopParams = @{ Monitor = $monitor }
Stop-DDUptimeMonitor @stopParams
