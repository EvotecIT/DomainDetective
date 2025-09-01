# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Auto-detect common selectors when none are provided
$Auto = Test-EmailDkim -DomainName 'evotec.pl' -Verbose
$Auto | Format-Table

# Explicit selectors
$Explicit = Test-EmailDkim -DomainName 'evotec.pl' -Selectors "selector1", "selector2"
$Explicit | Format-Table
