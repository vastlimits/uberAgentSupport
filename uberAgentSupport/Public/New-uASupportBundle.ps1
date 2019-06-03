#Requires -Version 3.0
#Requires -RunAsAdministrator
Function New-uASupportBundle {
    [CmdletBinding(SupportsShouldProcess = $False)]
    PARAM
    (
   
    )

    Begin {
        $ErrorActionPreference = 'Stop'
        Try {
            $stopWatch = [system.diagnostics.stopwatch]::startNew()
            $stopWatch.Start()
            $uAServiceLogs = "$env:windir\temp\uberAgent*.log"
            $uAInSessionHelperLog = "$env:windir\temp\uAInSessionHelper.log"
            $ProfilesDirectory = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory
            $UserProfiles = (Get-ChildItem -Path $ProfilesDirectory -Directory -Exclude 'Public').Name
            $WorkingDirectory = "$env:temp\uASupport"
            $PowerShellLog = "$WorkingDirectory\PowerShellTranskript.log"
            $OperatingSystem = (Get-CimInstance -Class Win32_OperatingSystem).caption
            $DesktopPath = [Environment]::GetFolderPath('Desktop')
            $OSBitness = $env:PROCESSOR_ARCHITECTURE
            $Processes = @('uberAgent','uAInSessionHelper')

            $RegKeysx86 = @(
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\vast limits' }
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\vast limits' }
                [PSCustomObject]@{Component = 'Chrome'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main' }
            )

            $RegKeysx64 = @(
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\vast limits' }
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\vast limits' }
                [PSCustomObject]@{Component = 'Chrome'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main' }
            )

            If ($OSBitness -eq 'AMD64') { $RegKeys = $RegKeysx64 } Else { $RegKeys = $RegKeysx86 }

            
            # Check for latest module version
            $LatestModuleVersion = $null
            $LatestModuleVersion = (Find-uAModule -Name uberAgentSupport).properties.version

            If ($LatestModuleVersion) {
                $InstalledModuleVersion = (Get-Module uberAgentSupport).Version

                If ($LatestModuleVersion -gt $InstalledModuleVersion) {
                    Write-Warning "Module version in PowerShell Gallery is '$LatestModuleVersion' while you are using '$InstalledModuleVersion'. Please update to the latest version with 'Update-Module uberAgentSupport'."
                }
                If ($LatestModuleVersion -eq $InstalledModuleVersion) {
                    Write-Verbose "Latest uberAgentSupport module version '$LatestModuleVersion' is installed." -Verbose
                }
            }
            Else {
                Write-Warning "Not able to get latest module version from PowerShell Gallery. Please check manually if you are using the latest module version."
            }
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            Throw $ErrorMessage
        }
    }
   
    Process {
        $ErrorActionPreference = 'Continue'
        Try {
            Start-Transcript -Path $PowerShellLog | Out-Null
            Write-Verbose 'Start' -Verbose
         
            Write-Verbose "Create working directory $WorkingDirectory" -Verbose
            New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null
         
            ###
            ### log files
            ###
            Write-Verbose 'Collect uberAgent service logs' -Verbose
            Copy-uAItem -Source $uAServiceLogs -Destination $WorkingDirectory

            Write-Verbose 'Collect In-Session helper log' -Verbose
            Copy-uAItem -Source $uAInSessionHelperLog -Destination $WorkingDirectory
         
            Write-Verbose 'Collect Chrome/Firefox browser extension in-session helper logs for all sessions' -Verbose
            foreach ($UserProfile in $UserProfiles) {
                Copy-uAItem -Source "$ProfilesDirectory\$UserProfile\AppData\Local\Temp\uAInSessionHelper.log" -Destination "$WorkingDirectory\uAInSessionHelper-$UserProfile.log"
            }

            Write-Verbose 'Collect Internet Explorer add-on log' -Verbose
            foreach ($UserProfile in $UserProfiles) {
                Copy-uAItem -Source "$ProfilesDirectory\$UserProfile\AppData\Local\Temp\Low\uberAgentIEExtension.log" -Destination "$WorkingDirectory\uberAgentIEExtension-$UserProfile.log"
            }
         
            Write-Verbose 'Collect Internet Explorer add-on log - Enhanced Protection Mode' -Verbose
            If ($OperatingSystem -match 'Microsoft Windows 7') {
                foreach ($UserProfile in $UserProfiles) {
                    Copy-uAItem -Source "$ProfilesDirectory\$UserProfile\AppData\Local\Temp\Low\uberAgentIEExtension.log" -Destination "$WorkingDirectory\uberAgentIEExtension-EPM-$UserProfile.log"
                }
            }
            Else {
                foreach ($UserProfile in $UserProfiles) {
                    Copy-uAItem -Source "$ProfilesDirectory\$UserProfile\AppData\Local\Packages\windows_ie_ac_001\AC\Temp\uberAgentIEExtension.log" -Destination "$WorkingDirectory\uberAgentIEExtension-EPM-$UserProfile.log"
                }
            }

            ###
            ### registry keys
            ###
            Write-Verbose 'Collect registry items' -Verbose
            New-Item -Path "$WorkingDirectory" -Name "Service registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory" -Name "Chrome registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory" -Name "Firefox registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory" -Name "Internet Explorer registry keys.txt" -ItemType File | Out-Null
            
            Foreach ($RegKey in $RegKeys) {
                $RegKeyContent = Get-uARegistryItem -Key "$($RegKey.Path)"
                $RegKeyComponent = "$($RegKey.Component)"
                Out-File -FilePath "$WorkingDirectory\$RegKeyComponent registry keys.txt" -InputObject $RegKeyContent -Append -NoClobber
            }

            ###
            ### running processes
            ###
            Write-Verbose 'Collect uberAgent process details' -Verbose
            Foreach ($Process in $Processes) {
                $ProcessDetail = Get-uAProcessDetails -ProcessName $Process
                Write-Verbose "Collect details for process $Process"
                Out-File -FilePath "$WorkingDirectory\Process details.txt" -InputObject $ProcessDetail -Append -NoClobber
            }

            ###
            ### zip file
            ###
            Write-Verbose 'Create support zip file' -Verbose
            $CurrentDate = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
            $ZipFilename = 'uASupportBundle-' + "$env:COMPUTERNAME" + '-' + "$CurrentDate" + '.zip'
            Compress-uAArchive -SourceDir $WorkingDirectory -ZipFilename $ZipFilename -ZipFilepath $DesktopPath
            Write-Verbose "Successfully created uberAgent support bundle at $(Join-Path $DesktopPath $ZipFilename)" -Verbose

            Write-Verbose 'Finish' -Verbose
        }
        Catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error $ErrorMessage
        }
      
        Finally {
            $stopWatch.Stop()
            Write-Verbose "Elapsed Runtime: $($stopWatch.Elapsed.Minutes) minutes and $($stopWatch.Elapsed.Seconds) seconds." -Verbose
            Stop-Transcript | Out-Null
            # Delete old working folder if any
            If (Test-Path $WorkingDirectory) {
                Remove-Item $WorkingDirectory -Force -Recurse -ErrorAction Stop
                Write-Verbose "Successfully deleted working directory '$WorkingDirectory'"
            }
        }
    }
}