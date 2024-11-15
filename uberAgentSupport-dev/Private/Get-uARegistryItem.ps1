Function Get-uARegistryItem {
    PARAM(
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$Key
    )

    # Correct key path if not correct
    If (!($Key.substring(0, 10) -ieq 'Registry::')) {
        Write-Verbose "Add 'Registry::' at the beginning of '$Key'"
        $Key = 'Registry::' + "$Key"
    }

    # Get content
    If (Test-Path $Key) {
        Write-Verbose "'$Key' exists"
        # Test for subkeys
        If ((Get-ChildItem -Path $Key).count -gt 0) {
            # Found subkeys
            $Result = Get-ChildItem -Path $Key -Recurse
        }
        Else {
            # No subkeys
            $Result = Get-Item $Key
        }
    }
    Else {
        Write-Verbose "'$Key' does not exist"
        $Result = $Null
    }

    Return $Result
}