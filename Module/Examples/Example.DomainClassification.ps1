Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DomainClassification = Test-DDMailDomainClassification -DomainName 'evotec.pl' -Verbose
$DomainClassification | Format-List

$DomainClassification = Test-DDMailDomainClassification -DomainName 'evo.yt' -Verbose
$DomainClassification | Format-List
