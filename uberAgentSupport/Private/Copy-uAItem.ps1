Function Copy-uAItem {
    PARAM(
        [Parameter(Mandatory = $True, Position = 0)]
        $Source,
        [Parameter(Mandatory = $True, Position = 1)]
        $Destination
    )

    If (Test-Path $Source) {
        Write-Verbose "Copy '$Source' to '$Destination'"
        Copy-Item -Path $Source -Destination $Destination
    }
    Else {
        Write-Warning "There is no file '$Source'"
    }
}