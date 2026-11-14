Describe 'Set-DDExportOptions SummaryColumnCap' {
    AfterAll {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Set-DDExportOptions -SummaryColumnCap 4 | Out-Null
    }

    It 'rejects retired layout overrides without changing defaults' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $before = [DomainDetective.PowerShell.ExportDefaults]::SummaryColumnCap
        { Set-DDExportOptions -SummaryColumnCap 6 -ErrorAction Stop } | Should -Throw
        [DomainDetective.PowerShell.ExportDefaults]::SummaryColumnCap | Should -Be $before
        { Set-DDExportOptions -SummaryColumnCap 4 -ErrorAction Stop } | Should -Not -Throw
    }

    It 'rejects out-of-range values' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Set-DDExportOptions -SummaryColumnCap 0 } | Should -Throw
        { Set-DDExportOptions -SummaryColumnCap 13 } | Should -Throw
    }
}
