Function Test-IsAbsolutePath {
    PARAM (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Path
    )

    if ($null -eq $Path -or $Path -eq "") {
        return $false
    }

    # Test if the path is absolute
    if ($Path -match '^[a-zA-Z]:\\' -or $Path.StartsWith('/')) {
        return $true
    }

    return $false
}

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

        # Check if the paths are absolute
        if ((Test-IsAbsolutePath -Path $Source) -ne $true) {
            Write-Warning "The Source path '$Source' is not an absolute path. Skipping copy action."
            return
        }

        if ((Test-IsAbsolutePath -Path $Destination) -ne $true) {
            Write-Warning "The Destination path '$Destination' is not an absolute path. Skipping copy action."
            return
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
        Write-Warning "The Source path '$Source' does not exist."
    }
}