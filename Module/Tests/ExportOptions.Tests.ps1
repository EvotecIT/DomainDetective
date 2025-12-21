Describe 'Set-DDExportOptions SummaryColumnCap' {
    AfterAll {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Set-DDExportOptions -SummaryColumnCap 4 | Out-Null
    }

    It 'accepts in-range values' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Set-DDExportOptions -SummaryColumnCap 6 } | Should -Not -Throw
        [DomainDetective.PowerShell.ExportDefaults]::SummaryColumnCap | Should -Be 6
    }

    It 'rejects out-of-range values' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Set-DDExportOptions -SummaryColumnCap 0 } | Should -Throw
        { Set-DDExportOptions -SummaryColumnCap 13 } | Should -Throw
    }
}
