Describe 'Test-DDEmailDkimRecord cmdlet' {
    It 'returns object when selector not found' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DDEmailDkimRecord -DomainName 'example.com' -Selectors 's1'
        $result | Should -Not -BeNullOrEmpty
        $result.DkimRecordExists | Should -BeFalse
    }
}
