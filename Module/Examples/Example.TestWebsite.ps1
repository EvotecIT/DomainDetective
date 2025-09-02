Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force


$Output = Test-DDWebStaticScan -Url "https://www.evotec.pl" -Verbose
$Output