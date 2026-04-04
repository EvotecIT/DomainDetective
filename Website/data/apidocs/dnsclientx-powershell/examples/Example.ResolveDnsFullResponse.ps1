Clear-Host

Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

$Output = Resolve-DnsQuery -Name '_25._tcp.mail.ietf.org' -Type TLSA -DnsProvider Cloudflare -Verbose -FullResponse
$Output.Questions | Format-Table
$Output.AnswersMinimal | Format-Table

$Output = Resolve-DnsQuery -Name 'github.com', 'evotec.pl', 'google.com' -Type TXT -DnsProvider Google -Verbose -FullResponse
$Output.Questions | Format-Table
$Output.AnswersMinimal | Format-Table

$Output = Resolve-DnsQuery -Name 'github.com', 'evotec.pl', 'google.com' -Type TXT -DnsProvider Cloudflare -Verbose -FullResponse
$Output.Questions | Format-Table
$Output.AnswersMinimal | Format-Table

$Output = Resolve-DnsQuery -Name 'github.com', 'evotec.pl', 'google.com' -Type TXT, A -Verbose -Server "192.168.241.5" -FullResponse
$Output.Questions | Format-Table
$Output.AnswersMinimal | Format-Table