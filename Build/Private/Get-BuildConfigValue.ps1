function Get-BuildConfigValue {
    <#
    .SYNOPSIS
    Reads an optional property value from a build configuration object.

    .DESCRIPTION
    Returns the named property value when it exists on the supplied configuration object.

    .PARAMETER Config
    The parsed build configuration object.

    .PARAMETER Name
    The property name to read.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Config,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $property = $Config.PSObject.Properties[$Name]
    if ($null -ne $property) {
        $property.Value
    }
}
