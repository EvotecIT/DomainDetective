Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Single run, multiple domains, one HTML file
Test-DDEmailSpfRecord -DomainName @('a.com','b.com','c.com') -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenReport

