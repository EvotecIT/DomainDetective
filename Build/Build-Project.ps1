#Requires -Modules PSPublishModule

[CmdletBinding()]
param(
    [string] $ConfigPath,
    [switch] $UpdateVersions,
    [switch] $Build,
    [switch] $PublishNuget,
    [switch] $PublishGitHub,
    [switch] $Plan,
    [string] $PlanPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Path $PSCommandPath -Parent
} else {
    (Get-Location).Path
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'project.build.json'
}

Import-Module PSPublishModule -Force -ErrorAction Stop

$invokeParams = @{
    ConfigPath = $ConfigPath
}

if ($PSBoundParameters.ContainsKey('UpdateVersions')) {
    $invokeParams.UpdateVersions = $UpdateVersions.IsPresent
}
if ($PSBoundParameters.ContainsKey('Build')) {
    $invokeParams.Build = $Build.IsPresent
}
if ($PSBoundParameters.ContainsKey('PublishNuget')) {
    $invokeParams.PublishNuget = $PublishNuget.IsPresent
}
if ($PSBoundParameters.ContainsKey('PublishGitHub')) {
    $invokeParams.PublishGitHub = $PublishGitHub.IsPresent
}
if ($PSBoundParameters.ContainsKey('Plan')) {
    $invokeParams.Plan = $Plan.IsPresent
}
if ($PlanPath) {
    $invokeParams.PlanPath = $PlanPath
}

Invoke-ProjectBuild @invokeParams
