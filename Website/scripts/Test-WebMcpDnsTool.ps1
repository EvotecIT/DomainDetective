[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $SiteRoot,

    [string] $BaseUrl
)

$ErrorActionPreference = 'Stop'
$resolvedSiteRoot = (Resolve-Path -LiteralPath $SiteRoot).Path
$runnerPath = Join-Path $PSScriptRoot 'webmcp-dns.playwright.js'
$playwrightPackage = '@playwright/cli@0.1.17'
$browserEngine = 'chromium'
$server = $null
$session = 'domaindetective-webmcp-dns-' + [Guid]::NewGuid().ToString('N')
$serverStandardOutputPath = Join-Path ([System.IO.Path]::GetTempPath()) "$session-server.stdout.log"
$serverStandardErrorPath = Join-Path ([System.IO.Path]::GetTempPath()) "$session-server.stderr.log"

try {
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
        $listener.Stop()
        $python = Get-Command python -ErrorAction Stop
        $serverArguments = @{
            FilePath = $python.Source
            ArgumentList = @('-m', 'http.server', $port, '--bind', '127.0.0.1', '--directory', $resolvedSiteRoot)
            PassThru = $true
            RedirectStandardOutput = $serverStandardOutputPath
            RedirectStandardError = $serverStandardErrorPath
        }
        if ($IsWindows) { $serverArguments.WindowStyle = 'Hidden' }
        $server = Start-Process @serverArguments
        $BaseUrl = "http://127.0.0.1:$port/tools/raw-dns-query/"
        $ready = $false
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri $BaseUrl -TimeoutSec 2
                if ($response.StatusCode -eq 200) { $ready = $true; break }
            } catch {
                Start-Sleep -Milliseconds 200
            }
        }
        if (-not $ready) { throw "Local DomainDetective server did not become ready at $BaseUrl." }
    }

    $npx = Get-Command npx -ErrorAction Stop
    $installOutput = & $npx.Source --yes --package $playwrightPackage playwright-cli install-browser $browserEngine 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Playwright could not install browser '$browserEngine'.`n$($installOutput -join [Environment]::NewLine)" }
    $openOutput = & $npx.Source --yes --package $playwrightPackage playwright-cli "-s=$session" open $BaseUrl --browser $browserEngine 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Playwright could not open the DNS tool.`n$($openOutput -join [Environment]::NewLine)" }
    $rawResult = & $npx.Source --yes --package $playwrightPackage playwright-cli "-s=$session" run-code --filename $runnerPath
    if ($LASTEXITCODE -ne 0) { throw 'Playwright WebMCP DNS run failed.' }
    $rawText = $rawResult -join [Environment]::NewLine
    $resultMatch = [regex]::Match($rawText, '(?ms)^### Result\r?\n(?<json>.+?)\r?\n### (?:Ran|Page|Error)')
    if (-not $resultMatch.Success) { throw "Playwright did not emit a parseable result block.`n$rawText" }
    $result = $resultMatch.Groups['json'].Value.Trim() | ConvertFrom-Json
    if ($result -is [string]) { $result = $result | ConvertFrom-Json }

    if ('query_dns_records' -notin @($result.registeredTools)) { throw 'The query_dns_records Website Tool was not registered.' }
    if (-not [bool] $result.annotations.readOnlyHint -or -not [bool] $result.annotations.untrustedContentHint) {
        throw 'The DNS Website Tool must declare read-only and untrusted-content annotations.'
    }
    if ([int] $result.schema.properties.name.maxLength -ne 253 -or @($result.schema.properties.type.enum).Count -gt 20) {
        throw 'The DNS Website Tool input schema is not explicitly bounded.'
    }
    if (-not [bool] $result.valid.success -or [string] $result.valid.name -ne 'example.com' -or [string] $result.valid.type -ne 'A') {
        throw 'The DNS Website Tool did not normalize and resolve the representative public query.'
    }
    if ([long] $result.validOutputCharacters -gt 1500) {
        throw "The DNS Website Tool returned $($result.validOutputCharacters) characters; the limit is 1500."
    }
    if ([string]::IsNullOrWhiteSpace([string] $result.visible.records) -or [string] $result.visible.status -notmatch '^Resolved via ') {
        throw 'The DNS Website Tool response was not left visible in the playground.'
    }
    if ([bool] $result.invalid.success -or [string] $result.invalidVisibleStatus -notmatch 'normalized public DNS name' -or -not [string]::IsNullOrWhiteSpace([string] $result.invalidVisibleRecords)) {
        throw 'The DNS Website Tool did not fail closed and synchronize the visible invalid-input state.'
    }
    if ([bool] $result.unsupported.success -or -not [string]::IsNullOrWhiteSpace([string] $result.unsupportedVisibleRecords)) {
        throw 'The DNS Website Tool did not clear stale records for an unsupported record type.'
    }
    if ([bool] $result.cancelled.success -or [string] $result.cancelledVisibleStatus -ne 'DNS query was cancelled.') {
        throw 'The DNS Website Tool did not honor a caller cancellation before network activity.'
    }
    $forwardedSpecialUse = @($result.specialUse | Where-Object { [bool] $_.output.success })
    if ($forwardedSpecialUse.Count -gt 0) {
        throw "The DNS Website Tool forwarded local or special-use names to the public resolver: $($forwardedSpecialUse.name -join ', ')."
    }
    if ([bool] $result.raceInvalid.success -or [bool] $result.superseded.success -or [string] $result.superseded.message -notmatch 'superseded' -or -not [string]::IsNullOrWhiteSpace([string] $result.raceVisible.records)) {
        throw 'The DNS Website Tool allowed a superseded request to replace the visible fail-closed state.'
    }
    if ([bool] $result.manuallySuperseded.success -or [string] $result.manuallySuperseded.message -notmatch 'superseded') {
        throw 'A manual invalid form submission did not return a structured superseded result to the pending Website Tool call.'
    }
    if (-not [bool] $result.lifecycle.disposed -or -not [bool] $result.lifecycle.removedAfterDispose -or -not [bool] $result.lifecycle.initialized -or -not [bool] $result.lifecycle.restoredAfterInit) {
        throw 'The DNS Website Tool did not follow the raw-query page lifecycle through its registration signal.'
    }
    if (@($result.consoleErrors).Count -gt 0) {
        throw "The DNS Website Tool emitted console errors: $($result.consoleErrors -join ' | ')"
    }

    Write-Output "DomainDetective WebMCP DNS tool verified at $BaseUrl ($($result.valid.totalAnswers) answers, $($result.validOutputCharacters) characters)."
} finally {
    $npxCommand = Get-Command npx -ErrorAction SilentlyContinue
    if ($npxCommand) { & $npxCommand.Source --yes --package $playwrightPackage playwright-cli "-s=$session" close 2>$null | Out-Null }
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit(5000) | Out-Null
    }
    if ($server) { $server.Dispose() }
    [System.IO.File]::Delete($serverStandardOutputPath)
    [System.IO.File]::Delete($serverStandardErrorPath)
}
