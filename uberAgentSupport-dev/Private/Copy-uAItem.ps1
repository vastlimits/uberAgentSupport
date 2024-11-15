Function Copy-uAItem {
    PARAM(
        [Parameter(Mandatory = $True, Position = 0)]
        $Source,
        [Parameter(Mandatory = $True, Position = 1)]
        $Destination,
        [switch]$Recurse,
        [string[]]$Exclude
    )

    If (Test-Path $Source) {
        # If the destination is a file, extract the directory part
        if ([System.IO.Path]::HasExtension($Destination)) {
            $DestinationDirectory = Split-Path $Destination -Parent
        } else {
            $DestinationDirectory = $Destination
        }

        # If the destination directory doesn't exist, create it
        if (-not (Test-Path $DestinationDirectory)) {
            New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
        }

        Write-Verbose "Copy '$Source' to '$Destination'" -Verbose

        $copyItemParams = @{
            Path = $Source
            Destination = $Destination
            Recurse = $Recurse
        }

        if ($Exclude) {
            $copyItemParams.Add("Exclude", $Exclude)
        }

        Copy-Item @copyItemParams
    }
    Else {
        Write-Warning "There is no file '$Source'"
    }
}