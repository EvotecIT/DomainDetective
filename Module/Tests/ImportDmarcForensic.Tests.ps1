Describe 'Import-DmarcForensic cmdlet' {
    It 'parses forensic report' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $b64 = Get-Content "$PSScriptRoot/../../DomainDetective.Tests/Data/dmarc_forensic.b64" -Raw
        $tmp = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($b64))
        $result = Import-DmarcForensic -Path $tmp
        Remove-Item $tmp -Force
        $result.SourceIp | Should -Be '192.0.2.1'
    }
}
