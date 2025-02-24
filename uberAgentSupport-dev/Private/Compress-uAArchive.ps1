Function Compress-uAArchive{
    [CmdletBinding(SupportsShouldProcess = $False)]
    PARAM
    (
        [Parameter(Mandatory = $True, Position = 0)]
        $SourceDir,
        
        [Parameter(Mandatory = $True, Position = 1)]
        $ZipFilename,
        
        [Parameter(Mandatory = $True, Position = 2)]
        $ZipFilepath
    )

    $ZipFile = Join-Path $ZipFilepath $ZipFilename

    #Prepare zip file
    if(-not (test-path($ZipFile))) {
        set-content $ZipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
        (Get-ChildItem $ZipFile).IsReadOnly = $false  
    }

    $shellApplication = new-object -com shell.application
    $zipPackage = $shellApplication.NameSpace($ZipFile)
    $items = Get-ChildItem -Path $SourceDir

    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            $files = Get-ChildItem -Path $item.FullName
            if ($files.Count -eq 0) {
                Write-Verbose "Skipping empty folder: $($item.FullName)"
                continue
            }
        }

        try {
            $zipPackage.CopyHere($item.FullName)
        } catch {
            Write-Error "Failed to copy $($item.FullName) to the zip package."
        }

        while ($null -eq $zipPackage.Items().Item($item.Name)) {
            Start-Sleep -Seconds 1
        }
    }
}