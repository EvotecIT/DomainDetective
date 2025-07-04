Describe 'Test-Arc cmdlet' {
    It 'supports pipeline input' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $path = "$PSScriptRoot/../../DomainDetective.Tests/Data/arc-valid.txt"
        $headers = Get-Content $path -Raw
        $result = $headers | Test-Arc
        $result | Should -Not -BeNullOrEmpty
    }
}

