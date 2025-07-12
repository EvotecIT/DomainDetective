# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$diff = Test-DnsPropagation -DomainName 'example.com' -RecordType A -SnapshotPath 'snapshots' -Diff
$diff
