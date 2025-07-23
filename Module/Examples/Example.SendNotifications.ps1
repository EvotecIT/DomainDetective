# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$monitor = Start-DnsPropagationMonitor -DomainName 'example.com' -RecordType A
$monitor.UseWebhook('https://example.com/hook')
$monitor.UseEmail('smtp.example.com', 25, $false, 'from@example.com', 'to@example.com')

# Run a single check
$monitor.RunAsync().Wait()

$monitor.Stop()
