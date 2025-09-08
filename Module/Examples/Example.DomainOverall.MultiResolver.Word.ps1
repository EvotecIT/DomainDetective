Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Domain = 'evotec.pl'

# Use two resolvers; FirstSuccess returns the first useful answer
$params = @{
    DomainName            = $Domain
    DnsEndpoints          = @(
        [DnsClientX.DnsEndpoint]::CloudflareWireFormat,
        [DnsClientX.DnsEndpoint]::Google
    )
    MultiResolverStrategy = 'FirstSuccess'
    ExportFormat          = 'Word'
    ExportPath            = (Join-Path $PSScriptRoot 'Reports')
    OpenReport            = $true
}

Test-DDDomainOverallHealth @params
