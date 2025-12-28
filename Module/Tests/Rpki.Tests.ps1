Describe 'Test-DDRpki cmdlet' {
    It 'executes without error' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-DDRpki -DomainName 'example.com' -DnsEndpoint System } | Should -Not -Throw
    }
    It 'downgrades query failures to warnings and records assessment code' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $logger = [DomainDetective.InternalLogger]::new($false)
        $warnings = [System.Collections.Generic.List[object]]::new()
        $logger.add_OnWarningMessage({
            param($sender, $eventArgs)
            $null = $warnings.Add($eventArgs)
        })
        $analysis = [DomainDetective.RPKIAnalysis]::new()
        $analysis.QueryDnsOverride = {
            param($name, $type)
            if ($type -eq [DnsClientX.DnsRecordType]::A) {
                $answer = [DnsClientX.DnsAnswer]::new()
                $answer.DataRaw = '192.0.2.10'
                $answer.Type = [DnsClientX.DnsRecordType]::A
                [System.Threading.Tasks.Task]::FromResult([DnsClientX.DnsAnswer[]]@($answer))
            } else {
                [System.Threading.Tasks.Task]::FromResult([DnsClientX.DnsAnswer[]]@())
            }
        }
        $analysis.QueryRpkiOverride = {
            param($ip)
            throw [System.Net.Http.HttpRequestException]::new("Service unavailable")
        }
        { $analysis.Analyze('example.com', $logger).GetAwaiter().GetResult() } | Should -Not -Throw
        ($analysis.Assessments | Select-Object -ExpandProperty Code) | Should -Contain 'RPKI.Query.Failed'
        ($warnings | ForEach-Object { $_.Code }) | Should -Contain 'RPKI.Query.Failed'
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-DDRpki -DomainName '' } | Should -Throw
}
}
