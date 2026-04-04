Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

# Test with a domain that has d365mktkey records (Microsoft domains often have these)
$T = Resolve-Dns -Type TXT -Name 'microsoft.com' -DnsProvider System -TypedRecords -ParseTypedTxtRecord
$T | Format-List

$T = Resolve-Dns -Type TXT -Name 'microsoft.com' -DnsProvider System -TypedRecords
$T | Format-Table