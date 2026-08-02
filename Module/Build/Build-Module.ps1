Import-Module PSPublishModule -Force

Build-Module -ModuleName 'DomainDetective' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        ModuleVersion        = '1.0.0'
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = 'a2986f0d-da11-43f5-a252-f9e1d1699776'
        Author               = 'Przemyslaw Klys'
        CompanyName          = 'Evotec'
        Copyright            = "(c) 2011 - $((Get-Date).Year) Przemyslaw Klys @ Evotec. All rights reserved."
        Description          = 'DomainDetective is a PowerShell module that provides features to work with domains, DNS, and other related information.'
        Tags                 = @('Windows', 'MacOS', 'Linux')
        #IconUri              = ''
        ProjectUri           = 'https://github.com/EvotecIT/DomainDetective'
        PowerShellVersion    = '5.1'
    }
    New-ConfigurationManifest @Manifest


    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $false
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSD1 and PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    New-ConfigurationFormat -ApplyTo 'OnMergePSM1', 'OnMergePSD1' -Sort None @ConfigurationFormat
    # format PSD1 and PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    New-ConfigurationFormat -ApplyTo 'DefaultPSD1', 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable -PathReadme 'Docs\Readme.md' -Path 'Docs' -SyncExternalHelpToProjectRoot

    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    $newConfigurationBuildSplat = @{
        Enable                               = $true
        SignModule                           = if ($Env:COMPUTERNAME -eq 'EVOMAGIC') { $true } else { $false }
        MergeModuleOnBuild                   = $true
        MergeFunctionsFromApprovedModules    = $true
        CertificateThumbprint                = '92e95fb58effa6a4a75e77a33cdd6bfe6dd30f1a'
        NETProjectPath                       = "$PSScriptRoot\..\..\DomainDetective.PowerShell"
        ResolveBinaryConflicts               = $true
        ResolveBinaryConflictsName           = 'DomainDetective.PowerShell'
        NETProjectName                       = 'DomainDetective.PowerShell'
        NETBinaryModule                      = 'DomainDetective.PowerShell.dll'
        NETConfiguration                     = 'Release'
        NETFramework                         = 'net8.0', 'net472'
        NETHandleAssemblyWithSameName        = $true
        NETAssemblyLoadContext               = $true
        DotSourceLibraries                   = $true
        DotSourceClasses                     = $true
        DeleteTargetModuleBeforeBuild        = $true
        RefreshPSD1Only                      = if ([string]::IsNullOrWhiteSpace($Env:RefreshPSD1Only)) { $false } else { [bool]::Parse($Env:RefreshPSD1Only) }
        NETBinaryModuleDocumentation         = $true
    }

    New-ConfigurationBuild @newConfigurationBuildSplat

    New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked" -RequiredModulesPath "$PSScriptRoot\..\Artefacts\Unpacked\Modules"
    New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -IncludeTagName

    # global options for publishing to github/psgallery
    #New-ConfigurationPublish -Type PowerShellGallery -FilePath 'C:\Support\Important\PowerShellGalleryAPI.txt' -Enabled:$false
    #New-ConfigurationPublish -Type GitHub -FilePath 'C:\Support\Important\GitHubAPI.txt' -UserName 'EvotecIT' -Enabled:$false -GenerateReleaseNotes
}
