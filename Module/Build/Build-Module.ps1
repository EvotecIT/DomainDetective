param(
    [ValidateSet('Manifest', 'Documentation', 'Build', 'Publish')]
    [string] $ConfigurationGateMode = 'Build',

    [bool] $SignModule = $false,

    [string] $ProjectBuildConfigPath = '..\Build\project.build.json',

    [string] $NuGetApiKeyPath = 'C:\Support\Important\NugetOrgEvotec.txt',

    [string] $PowerShellGalleryApiKeyPath = 'C:\Support\Important\PowerShellGalleryAPI.txt',

    [string] $GitHubApiKeyPath = 'C:\Support\Important\GitHubAPI.txt'
)

Import-Module PSPublishModule -MinimumVersion '3.0.130' -Force -ErrorAction Stop

Build-Module -ModuleName 'DomainDetective' {
    # Usual defaults as per standard module
    $Manifest = [ordered] @{
        ModuleVersion        = '1.0.X'
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
        SignModule                           = $SignModule
        MergeModuleOnBuild                   = $true
        MergeFunctionsFromApprovedModules    = $true
        CertificateThumbprint                = '92e95fb58effa6a4a75e77a33cdd6bfe6dd30f1a'
        NETProjectPath                       = '..\DomainDetective.PowerShell\DomainDetective.PowerShell.csproj'
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
        NETBinaryModuleDocumentation         = $true
    }

    New-ConfigurationBuild @newConfigurationBuildSplat

    $projectBuildOptions = @{
        PublishApiKeyFilePath = $NuGetApiKeyPath
    }
    New-ConfigurationProjectBuild -Name 'DomainDetective' -ConfigPath $ProjectBuildConfigPath -Enabled -BuildBeforeModule -ProvideLocalNuGetFeed -PublishNuget -Options $projectBuildOptions
    New-ConfigurationRelease -StageRoot 'Artefacts\UploadReady' -VersionSource Module -BuildOrder 'Packages', 'Module' -PublishOrder 'NuGet', 'PowerShellGallery', 'GitHub'

    New-ConfigurationArtefact -Type Unpacked -Enable -Path 'Artefacts\Unpacked' -RequiredModulesPath 'Artefacts\Unpacked\Modules'
    New-ConfigurationArtefact -Type Packed -Enable -Path 'Artefacts\Packed' -IncludeTagName -ArtefactName 'DomainDetective-PowerShellModule.<TagModuleVersionWithPreRelease>.zip' -ID 'ToGitHub'

    # global options for publishing to github/psgallery
    New-ConfigurationPublish -Type PowerShellGallery -FilePath $PowerShellGalleryApiKeyPath -Enabled:$false
    New-ConfigurationPublish -Type GitHub -FilePath $GitHubApiKeyPath -UserName 'EvotecIT' -RepositoryName 'DomainDetective' -Enabled:$false -GenerateReleaseNotes -OverwriteTagName 'DomainDetective-PowerShellModule.<TagModuleVersionWithPreRelease>'

    New-ConfigurationGate -Mode $ConfigurationGateMode
} -ExitCode
