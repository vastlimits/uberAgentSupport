function Find-uAModule {
    param($Name)
    Try {
       $Module = $null
       $Module = Invoke-RestMethod "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$Name' and IsLatestVersion"
       
       If ($Module) {
           return $Module
       }
       Else {
           return $null
       }
    }
    Catch {
       return $null
    }
}