Describe 'Test-DDEmailMtaSts cmdlet' {
    It 'returns MtastsInfo view' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DDEmailMtaSts -DomainName 'example.com' -ErrorAction SilentlyContinue
        $result | Should -BeOfType 'DomainDetective.Views.MtastsInfo'
    }
}
