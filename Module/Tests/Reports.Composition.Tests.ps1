Describe 'Reporting composition surface' {
    It 'exposes Export-DDSecurityReport' {
        Get-Command Export-DDSecurityReport -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }
    It 'SPF cmdlet DomainName parameter accepts string[]' {
        $p = (Get-Command Test-DDEmailSpfRecord).Parameters['DomainName']
        $p.ParameterType.FullName | Should -Be 'System.String[]'
    }
    It 'DMARC cmdlet DomainName parameter accepts string[]' {
        $p = (Get-Command Test-DDEmailDmarcRecord).Parameters['DomainName']
        $p.ParameterType.FullName | Should -Be 'System.String[]'
    }
    It 'DKIM cmdlet DomainName parameter accepts string[]' {
        $p = (Get-Command Test-DDEmailDkimRecord).Parameters['DomainName']
        $p.ParameterType.FullName | Should -Be 'System.String[]'
    }
}

