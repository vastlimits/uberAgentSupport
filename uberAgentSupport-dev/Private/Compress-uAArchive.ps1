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
    $files = Get-ChildItem -Path $SourceDir

    foreach($file in $files) { 
        $zipPackage.CopyHere($file.FullName)
        #using this method, sometimes files can be 'skipped'
        #this 'while' loop checks each file is added before moving to the next
        while($null -eq $zipPackage.Items().Item($file.name)){
            Start-sleep -seconds 1
        }
    }
}