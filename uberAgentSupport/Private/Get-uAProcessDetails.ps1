function Get-uAProcessDetails {
    [CmdletBinding()]
    param (
        # process name
        [Parameter(Mandatory = $true)]
        [string]
        $ProcessName
    )
    $owners = @{ }
    $ProcessNameExt = $ProcessName + '.exe'
    Get-WmiObject win32_process -Filter "Name='$ProcessNameExt'" | ForEach-Object { $owners[$_.handle] = $_.getowner().user }
    Get-Process -Name $ProcessName | Select-Object processname, Id, @{l = "Owner"; e = { $owners[$_.id.tostring()] } }
    
    return $owners
}