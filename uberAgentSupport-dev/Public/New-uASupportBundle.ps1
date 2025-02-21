#Requires -Version 5.1
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

            # Evaluate log file path
            $null = $LogPath
            if (Test-Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig") {
                $LogPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig" -Name LogPath -ErrorAction SilentlyContinue
            }
            if (-not $LogPath) {
                if (Test-Path "HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig") {
                    $LogPath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig" -Name LogPath -ErrorAction SilentlyContinue
                }
                else {
                    Write-Verbose "LogPath not found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'. Trying 'HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig'." -Verbose
                }
            }
            else {
                Write-Verbose "LogPath found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'." -Verbose
            }
            if (-not $LogPath)
            {
                Write-Verbose "LogPath not found in 'HKLM:\SOFTWARE\vast limits\uberAgent\LogConfig'. Using default path." -Verbose
                $LogPath = "$env:windir\temp"
            }
            else
            {
                Write-Verbose "LogPath found in 'HKLM:\SOFTWARE\Policies\vast limits\uberAgent\LogConfig'." -Verbose
            }
            
            $ResolvedLogPath = [System.Environment]::ExpandEnvironmentVariables($LogPath)
            Write-Verbose "Resolved log path: $ResolvedLogPath" -Verbose

            # Test access to log path
            if (-not $(Test-Path -Path $ResolvedLogPath))
            {
                Throw "Log path '$ResolvedLogPath' not found. Please check the log path configuration or verify that you have the permissions to access the log path."
            }

            $uAServiceLogs = [System.IO.Path]::Combine($ResolvedLogPath, "uberAgent*.log")
            $uAServiceConfigurationLogs = [System.IO.Path]::Combine($ResolvedLogPath, "uberAgentServiceConfig*.log")
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
                $ProfilesDirectory = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory
            } else {
                Throw "Registry key 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' not found."
            }
            $uAInSessionHelperLog = [System.IO.Path]::Combine($ResolvedLogPath, "uAInSessionHelper.log")
            $ProfilesDirectory = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory
            $UserProfiles = (Get-ChildItem -Path $ProfilesDirectory -Directory -Exclude 'Public').Name
            $WorkingDirectory = [System.IO.Path]::Combine($env:temp, "uASupport")
            $PowerShellLog = [System.IO.Path]::Combine($WorkingDirectory, "PowerShellTranskript.log")
            $OperatingSystem = (Get-CimInstance -Class Win32_OperatingSystem).caption
            $DesktopPath = [Environment]::GetFolderPath('Desktop')
            $OSBitness = $env:PROCESSOR_ARCHITECTURE
            $Processes = @('uberAgent','uAInSessionHelper')
            $UninstallPaths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
            $uberAgentInstallDir = ($UninstallPaths | ForEach-Object {Get-ItemProperty $_} | Where-Object Displayname -match "uberAgent").InstallLocation
            $SplunkUFservice = "SplunkForwarder"
            $ExcludeExecutablesAndLibraries = @('*.exe','*.dll','*.sys','*.msi')

            $RegKeysx86 = @(
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\vast limits' }
                [PSCustomObject]@{Component = 'Service'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\vast limits' }
                [PSCustomObject]@{Component = 'Chrome'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Firefox'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Mozilla\NativeMessagingHosts\com.vastlimits.uainsessionhelper' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_CLASSES_ROOT\CLSID\{82004312-5B53-46F1-B179-4FCE28048E6F}\InProcServer32' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE' }
                [PSCustomObject]@{Component = 'Internet Explorer'; Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UberAgentDrv' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uberAgentNetMon' }
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
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\UberAgentDrv' }
                [PSCustomObject]@{Component = 'Driver'; Path = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\uberAgentNetMon' }
            )

            If ($OSBitness -eq 'AMD64') { $RegKeys = $RegKeysx64 } Else { $RegKeys = $RegKeysx86 }

            If ((Get-Service).Name -contains $SplunkUFservice) {
               $SplunkUFinstalled = $True
               $SplunkUFInstallDir = (($UninstallPaths | ForEach-Object {Get-ItemProperty $_} | Where-Object Displayname -match "UniversalForwarder").InstallLocation).TrimEnd("\")
               $Processes += 'splunkd'
            }
            Else {
               $SplunkUFinstalled = $False
            }

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

            #region log files
            Write-Verbose 'Collect uberAgent service logs' -Verbose
            Copy-uAItem -Source $uAServiceLogs -Destination "$WorkingDirectory\Service"

            Write-Verbose 'Collect uberAgent service configuration logs' -Verbose
            Copy-uAItem -Source $uAServiceConfigurationLogs -Destination "$WorkingDirectory\Service"

            Write-Verbose 'Collect In-Session helper log' -Verbose
            Copy-uAItem -Source $uAInSessionHelperLog -Destination "$WorkingDirectory\uAInSessionHelper"

            Write-Verbose 'Collect Chrome/Firefox browser extension in-session helper logs for all sessions' -Verbose
            

            foreach ($UserProfile in $UserProfiles) {
                $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\uAInSessionHelper.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uAInSessionHelper-$UserProfile.log")

                Copy-uAItem -Source $src -Destination $dst
            }

            Write-Verbose 'Collect Internet Explorer add-on log' -Verbose
            foreach ($UserProfile in $UserProfiles) {
                $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\Low\uberAgentIEExtension.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-$UserProfile.log")
                Copy-uAItem -Source $src -Destination $dst
            }

            Write-Verbose 'Collect Internet Explorer add-on log - Enhanced Protection Mode' -Verbose
            If ($OperatingSystem -match 'Microsoft Windows 7') {
                foreach ($UserProfile in $UserProfiles) {
                    $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Temp\Low\uberAgentIEExtension.log")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-EPM-$UserProfile.log")
                    Copy-uAItem -Source $src -Destination $dst
                }
            }
            Else {
                foreach ($UserProfile in $UserProfiles) {
                    $src = [System.IO.Path]::Combine($ProfilesDirectory, $UserProfile, "AppData\Local\Packages\windows_ie_ac_001\AC\Temp\uberAgentIEExtension.log")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Browser", "uberAgentIEExtension-EPM-$UserProfile.log")
                    Copy-uAItem -Source $src -Destination $dst
                }
            }

            If($SplunkUFinstalled) {
                Write-Verbose 'Collect Splunk Universal Forwarder logs' -Verbose

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "var\log\splunk\splunkd.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "splunkd.log")
                Copy-uAItem -Source $src -Destination $dst

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "var\log\splunk\metrics.log")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "metrics.log")
                Copy-uAItem -Source $src -Destination $dst

                Write-Verbose 'Performing uberAgent to Splunk Universal Forwarder connection check' -Verbose
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "Get-NetTCPConnection.log")
                Get-NetTCPConnection | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File -FilePath $dst
            }
            #endregion log files

            #region config files
            Write-Verbose 'Collect uberAgent configuration files' -Verbose
            New-Item -Path "$WorkingDirectory" -Name Config -ItemType Directory | Out-Null

            $src = [System.IO.Path]::Combine($env:programdata, "vast limits\uberAgent\Configuration\*")
            $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\ProgramData")
            Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries
            
            $src = [System.IO.Path]::Combine($uberAgentInstallDir, "*")
            $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\ProgramFiles")
            Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries

            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\vast limits\uberAgent\Config" -Name ConfigFilePath -ErrorAction SilentlyContinue) -OR (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\vast limits\uberAgent\Config" -Name ConfigFilePath -ErrorAction SilentlyContinue)) {
                # CCFM is active
                $ConfigCachePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\vast limits\uberAgent\CCFM" -Name ConfigCachePath).ConfigCachePath
                if ($ConfigCachePath)
                {
                    $src = [System.IO.Path]::Combine($ConfigCachePath, "*")
                    $dst = [System.IO.Path]::Combine($WorkingDirectory, "Config\CCFM")
                    Copy-uAItem -Source $src -Destination $dst -Recurse -Exclude $ExcludeExecutablesAndLibraries
                }
                else {
                    Write-Warning "ConfigFilePath is set but ConfigCachePath is not. CCFM config is broken."
                }

            }

            If($SplunkUFinstalled) {
                Write-Verbose 'Collect Splunk Universal Forwarder configuration files' -Verbose

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "etc\system\local\inputs.conf")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "inputs.conf")
                Copy-uAItem -Source $src -Destination $dst

                $src = [System.IO.Path]::Combine($SplunkUFInstallDir, "etc\system\local\outputs.conf")
                $dst = [System.IO.Path]::Combine($WorkingDirectory, "SplunkUniversalForwarder", "outputs.conf")
                Copy-uAItem -Source $src -Destination $dst
            }
            #endregion config files

            #region registry
            Write-Verbose 'Collect registry items' -Verbose
            New-Item -Path "$WorkingDirectory\Registry" -ItemType Directory | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Service registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Chrome registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Firefox registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Internet Explorer registry keys.txt" -ItemType File | Out-Null
            New-Item -Path "$WorkingDirectory\Registry" -Name "Driver registry keys.txt" -ItemType File | Out-Null

            Foreach ($RegKey in $RegKeys) {
                $RegKeyContent = Get-uARegistryItem -Key "$($RegKey.Path)"
                $RegKeyComponent = "$($RegKey.Component)"

                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Registry", "$RegKeyComponent registry keys.txt")
                Out-File -FilePath $dst -InputObject $RegKeyContent -Append -NoClobber
            }
            #endregion registry

            #region processes
            Write-Verbose 'Collect uberAgent process details' -Verbose
            New-Item -Path "$WorkingDirectory\Processes" -ItemType Directory | Out-Null
            Foreach ($Process in $Processes) {
                $ProcessDetail = Get-uAProcessDetails -ProcessName $Process

                Write-Verbose "Collect details for process $Process"

                $dst = [System.IO.Path]::Combine($WorkingDirectory, "Processes", "Process details.txt")

                Out-File -FilePath $dst -InputObject $ProcessDetail -Append -NoClobber
            }
            #endregion processes

            #region zip file
            Write-Verbose 'Create support zip file' -Verbose
            $CurrentDate = Get-Date -Format "yyyy-MM-dd HH-mm-ss"
            $ZipFilename = 'uASupportBundle-' + "$env:COMPUTERNAME" + '-' + "$CurrentDate" + '.zip'

            Compress-uAArchive -SourceDir $WorkingDirectory -ZipFilename $ZipFilename -ZipFilepath $DesktopPath
            Write-Verbose "Successfully created uberAgent support bundle at $(Join-Path $DesktopPath $ZipFilename)" -Verbose
            #endregion zip file

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

                if ((Test-IsAbsolutePath -Path $WorkingDirectory) -eq $true) {
                    Remove-Item $WorkingDirectory -Force -Recurse -ErrorAction Stop
                    Write-Verbose "Successfully deleted working directory '$WorkingDirectory'"
                }
                else {
                    Write-Error "Failed to delete working directory '$WorkingDirectory'"
                }
                
            }
        }
    }
}