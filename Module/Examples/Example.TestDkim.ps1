# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DkimRecord -DomainName 'evotec.pl' -Verbose -Selectors "selector1", "selector2"
$Results | Format-Table

$Results.AnalysisResults | Format-Table

$Results.AnalysisResults.Values

$Results.AnalysisResults.Values | Out-HtmlView -ScrollX -Filtering -DataStore JavaScript
