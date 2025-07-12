Describe 'Test-DnsPropagation cmdlet' {
    It 'accepts CountryCount parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DnsPropagation -DomainName 'example.com' -RecordType A -CountryCount @{PL=0}
        $result | Should -BeNullOrEmpty
    }

    It 'creates snapshot file' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $dir = Join-Path $TestDrive 'snapshots'
        $null = Test-DnsPropagation -DomainName 'example.com' -RecordType A -CountryCount @{PL=0} -SnapshotPath $dir
        (Get-ChildItem $dir).Count | Should -Be 1
    }

    It 'returns diff output' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $dir = Join-Path $TestDrive 'snapshots'
        $first = Test-DnsPropagation -DomainName 'example.com' -RecordType A -CountryCount @{PL=0} -SnapshotPath $dir
        $diff = Test-DnsPropagation -DomainName 'example.com' -RecordType A -CountryCount @{PL=0} -SnapshotPath $dir -Diff
        $diff | Should -BeNullOrEmpty
    }
}
