Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainClassification = Get-DDMailDomainClassification -DomainName 'evotec.pl' -Verbose
$DomainClassification | Format-List


$DomainClassification = Get-DDMailDomainClassification -DomainName 'evo.yt' -Verbose
$DomainClassification | Format-List