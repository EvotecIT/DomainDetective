function ConvertTo-BuildArray {
    <#
    .SYNOPSIS
    Converts an optional value to a PowerShell array.

    .DESCRIPTION
    Returns an empty array for null input and a single PowerShell array wrapper for all other values.

    .PARAMETER Value
    The value to convert.
    #>
    param(
        $Value
    )

    if ($null -eq $Value) {
        @()
        return
    }

    @($Value)
}
