$ErrorActionPreference = 'Stop'

# Multi-domain mail classification, one Word file
Test-DDMailDomainClassification -DomainName @('contoso.com','fabrikam.com','adatum.com') -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport
