Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force


$Output = Test-DDWebsiteStaticScan -Url "https://www.evotec.pl" -Verbose
$Output