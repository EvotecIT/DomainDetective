[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DeployWorkflowPath,

    [Parameter(Mandatory = $true)]
    [string] $PipelinePath
)

$ErrorActionPreference = 'Stop'

function Get-ResolvedPipelineSteps {
    <#
    .SYNOPSIS
    Resolves PowerForge pipeline steps, including inherited parent pipeline files.

    .DESCRIPTION
    Reads a PowerForge pipeline JSON file and returns the combined parent and local step list so deployment guardrails can be validated against the effective pipeline.

    .PARAMETER PipelinePath
    Path to the pipeline JSON file.

    .PARAMETER Visited
    Tracks visited pipeline files and prevents recursion loops.

    .EXAMPLE
    Get-ResolvedPipelineSteps -PipelinePath 'Website/pipeline.json' -Visited ([System.Collections.Generic.HashSet[string]]::new())
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $PipelinePath,

        [System.Collections.Generic.HashSet[string]] $Visited
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($PipelinePath)
    if (-not $Visited.Add($resolvedPath)) {
        @()
    } else {
        if (-not (Test-Path -LiteralPath $resolvedPath)) {
            throw "Pipeline config not found: $resolvedPath"
        }

        $document = Get-Content -LiteralPath $resolvedPath -Raw | ConvertFrom-Json
        $documentProperties = @($document.PSObject.Properties.Name)
        $steps = [System.Collections.Generic.List[object]]::new()

        if ($documentProperties -contains 'extends' -and -not [string]::IsNullOrWhiteSpace([string] $document.extends)) {
            $parentPath = Join-Path -Path ([System.IO.Path]::GetDirectoryName($resolvedPath)) -ChildPath ([string] $document.extends)
            foreach ($parentStep in @(Get-ResolvedPipelineSteps -PipelinePath $parentPath -Visited $Visited)) {
                $steps.Add($parentStep)
            }
        }

        if ($documentProperties -contains 'steps' -and $null -ne $document.steps) {
            foreach ($step in @($document.steps)) {
                $steps.Add($step)
            }
        }

        $steps.ToArray()
    }
}

if (-not (Test-Path -LiteralPath $DeployWorkflowPath)) {
    throw "Deploy workflow not found: $DeployWorkflowPath"
}

$deployWorkflow = Get-Content -LiteralPath $DeployWorkflowPath -Raw
if ($deployWorkflow -notmatch 'powerforge-website-deploy\.yml@') {
    throw "Deploy workflow must call the PowerForge website deploy reusable workflow."
}

$guardrailMatch = [regex]::Match($deployWorkflow, '(?m)^\s*require_seo_doctor_guardrail:\s*(true|false)\s*(?:#.*)?$')
$requiresSeoDoctorGuardrail = $true
if ($guardrailMatch.Success) {
    $requiresSeoDoctorGuardrail = [bool]::Parse($guardrailMatch.Groups[1].Value)
}

$visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$steps = @(Get-ResolvedPipelineSteps -PipelinePath $PipelinePath -Visited $visited)

[array] $seoDoctorSteps = foreach ($step in $steps) {
    $stepProperties = @($step.PSObject.Properties.Name)
    if ($stepProperties -contains 'task' -and
        [string]::Equals([string] $step.task, 'seo-doctor', [System.StringComparison]::OrdinalIgnoreCase)) {
        $step
    }
}

[array] $gatingSeoDoctorSteps = foreach ($step in $seoDoctorSteps) {
    $stepProperties = @($step.PSObject.Properties.Name)
    if (($stepProperties -contains 'failOnWarnings' -and $step.failOnWarnings -eq $true) -or
        ($stepProperties -contains 'failOnNewIssues' -and $step.failOnNewIssues -eq $true) -or
        ($stepProperties -contains 'failOnNew' -and $step.failOnNew -eq $true)) {
        $step
    }
}

[array] $fullyConfiguredSeoDoctorSteps = foreach ($step in $gatingSeoDoctorSteps) {
    $stepProperties = @($step.PSObject.Properties.Name)
    if ($stepProperties -contains 'checkContentLeaks' -and $step.checkContentLeaks -eq $true -and
        $stepProperties -contains 'requireCanonical' -and $step.requireCanonical -eq $true -and
        $stepProperties -contains 'requireHreflang' -and $step.requireHreflang -eq $true -and
        $stepProperties -contains 'requireHreflangXDefault' -and $step.requireHreflangXDefault -eq $true) {
        $step
    }
}

if ($requiresSeoDoctorGuardrail) {
    if ($fullyConfiguredSeoDoctorSteps.Count -eq 0) {
        throw "Deploy workflow enables require_seo_doctor_guardrail, but the effective pipeline does not contain a gating seo-doctor step with checkContentLeaks, canonical, hreflang, and x-default checks."
    }

    Write-Host "Deploy contract validated with $($fullyConfiguredSeoDoctorSteps.Count) fully configured seo-doctor step(s)."
} else {
    [array] $doctorSteps = foreach ($step in $steps) {
        $stepProperties = @($step.PSObject.Properties.Name)
        if ($stepProperties -contains 'task' -and
            [string]::Equals([string] $step.task, 'doctor', [System.StringComparison]::OrdinalIgnoreCase)) {
            $step
        }
    }

    [array] $gatingDoctorSteps = foreach ($step in $doctorSteps) {
        $stepProperties = @($step.PSObject.Properties.Name)
        if (($stepProperties -contains 'failOnWarnings' -and $step.failOnWarnings -eq $true) -or
            ($stepProperties -contains 'failOnNewIssues' -and $step.failOnNewIssues -eq $true) -or
            ($stepProperties -contains 'failOnNew' -and $step.failOnNew -eq $true)) {
            $step
        }
    }

    if ($gatingDoctorSteps.Count -eq 0) {
        throw "Deploy workflow opts out of seo-doctor guardrails, but the effective pipeline does not contain a gating doctor audit step."
    }

    Write-Host "Deploy contract validated with seo-doctor guardrail intentionally disabled and $($gatingDoctorSteps.Count) gating doctor audit step(s)."
}
