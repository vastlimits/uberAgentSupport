function Get-uAProcessDetails {
    [CmdletBinding()]
    param (
        # process name
        [Parameter(Mandatory = $true)]
        [string]
        $ProcessName
    )
    $owners = @()
    $ProcessNameExt = $ProcessName + '.exe'
    
    Get-CimInstance Win32_Process -Filter "name = '$ProcessNameExt'" | ForEach-Object {
       $Owner = (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).user
       $Id = $_.Handle
       
       $Properties = @{Name = "$ProcessName"; Id = $Id; Owner = "$Owner"}
       $Newobject = New-Object PSObject -Property $Properties
       $owners += $Newobject
    }
    
    return $owners
}